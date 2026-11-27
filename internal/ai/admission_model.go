// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/lens"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// DefaultAdmissionConfidence is the confidence the model must give an asset
// for it to be admitted into scope (0..100).
const DefaultAdmissionConfidence = 80

// AdmissionModel lets the main model decide, on its own, the admissions the
// evidence leaves open: an asset tied to an in-scope organization by
// supporting evidence only. It decides in the background (the scope parks
// whatever waits on it), and its decisions are recorded like any automatic
// one, so the user is told during and after the run and can undo them.
type AdmissionModel struct {
	Model   llm.Model
	ModelID string
	// MinConfidence is the model confidence needed to admit; 0 uses
	// DefaultAdmissionConfidence.
	MinConfidence int
	// Breaker, shared with the session's other deciders, stops asking a
	// model that keeps failing; the evidence rule then decides. Nil never
	// stops.
	Breaker *ModelBreaker
}

var _ et.AdmissionDecider = (*AdmissionModel)(nil)

// Name implements et.AdmissionDecider.
func (a *AdmissionModel) Name() string {
	return "model " + a.ModelID
}

// Decide implements et.AdmissionDecider. It takes a request with evidence,
// none of it strong, for an organization; anything else is left to the
// evidence rule.
func (a *AdmissionModel) Decide(_ context.Context, _ et.Session, req *et.AdmissionRequest) (et.AdmissionVerdict,
	bool, error) {
	if a == nil || a.Model == nil || req == nil || req.For == nil || len(req.Evidence) == 0 || !a.Breaker.Allow() {
		return et.AdmissionVerdict{}, false, nil
	}
	for _, ev := range req.Evidence {
		if ev.Strength == et.StrengthStrong {
			return et.AdmissionVerdict{}, false, nil
		}
	}

	return et.AdmissionVerdict{Outcome: et.Pending, Later: func(ctx context.Context) (et.AdmissionVerdict, error) {
		return a.ask(ctx, req)
	}}, true, nil
}

const admissionInstructions = `You decide whether an asset belongs to an organization closely enough that an attack-surface enumeration should investigate it as the organization's own.
Use only the evidence given. Each piece names a signal, what it means and when it can mislead.
Admit only when the evidence taken together makes common ownership or control more likely than not, and nothing in it points to a third party instead: a hosting or email provider, a registrar, a marketing agency, a shared platform or a template.
Reply with JSON: decision "admit" or "reject", confidence from 0 to 1 that your decision is right, and a one-sentence reason that names the evidence it rests on.`

var admissionSchema = llm.JSONSchema{Name: "admission_decision",
	Description: "Whether to admit the asset into the enumeration's scope",
	Schema: map[string]any{"type": "object", "additionalProperties": false,
		"required": []string{"decision", "confidence", "reason"},
		"properties": map[string]any{
			"decision":   map[string]any{"type": "string", "enum": []string{"admit", "reject"}},
			"confidence": map[string]any{"type": "number", "minimum": 0, "maximum": 1},
			"reason":     map[string]any{"type": "string"},
		}}}

func (a *AdmissionModel) ask(ctx context.Context, req *et.AdmissionRequest) (et.AdmissionVerdict, error) {
	// admissions queued before the model was stopped are not asked either
	if !a.Breaker.Allow() {
		return et.AdmissionVerdict{}, ErrModelStopped
	}
	history := []llm.Message{{Role: "system", Text: admissionInstructions}, {Role: "user", Text: admissionCase(req)}}
	var reply struct {
		Decision   string  `json:"decision"`
		Confidence float64 `json:"confidence"`
		Reason     string  `json:"reason"`
	}
	err := decodeJSON(ctx, a.Model, history, admissionSchema, &reply)
	a.Breaker.Record(requestErr(err))
	if err != nil {
		return et.AdmissionVerdict{}, err
	}

	conf := int(min(max(reply.Confidence, 0), 1) * 100)
	reason := strings.TrimSpace(reply.Reason)
	if len(reason) > 400 {
		reason = reason[:400]
	}
	// the model's own bar, or the expansion policy's when that is higher
	need := a.MinConfidence
	if need <= 0 {
		need = DefaultAdmissionConfidence
	}
	need = max(need, req.PolicyConfidence)
	if reply.Decision == "admit" && conf >= need {
		return et.AdmissionVerdict{Outcome: et.Admitted, Confidence: conf, Rationale: reason,
			Conclusion: et.Admitted}, nil
	}
	if reply.Decision == "admit" {
		return et.AdmissionVerdict{Outcome: et.Rejected, Confidence: conf, Conclusion: et.Admitted,
			Rationale: fmt.Sprintf("the model leaned to admit at confidence %d, below %d: %s", conf, need, reason)}, nil
	}
	return et.AdmissionVerdict{Outcome: et.Rejected, Confidence: conf, Rationale: reason, Conclusion: et.Rejected}, nil
}

// admissionCase describes the request for the model: the organization, the
// asset, how it was reached and each piece of evidence with what the signal
// catalog says of it.
func admissionCase(req *et.AdmissionRequest) string {
	var b strings.Builder
	org := req.For.Asset.Key()
	if o, ok := req.For.Asset.(*oamorg.Organization); ok && o.Name != "" {
		org = o.Name
	}
	a := req.Entity.Asset
	fmt.Fprintf(&b, "Organization: %s\nAsset: %s %s\n", org, a.AssetType(), a.Key())
	if req.Via != "" {
		fmt.Fprintf(&b, "Reached by: %s\n", req.Via)
	}
	if req.Confidence > 0 {
		fmt.Fprintf(&b, "Score from the signal weights: %d of 100\n", req.Confidence)
	}

	b.WriteString("Evidence:\n")
	for _, ev := range req.Evidence {
		fmt.Fprintf(&b, "- %s (%s)", ev.Signal, ev.Strength)
		if def, ok := signalDefinition(ev.Signal); ok {
			fmt.Fprintf(&b, ": %s. Why it counts: %s", def.Title, def.Rationale)
			if len(def.CounterIndications) > 0 {
				fmt.Fprintf(&b, " Can mislead when: %s", strings.Join(def.CounterIndications, " "))
			}
		}
		b.WriteString("\n")
		if ev.Detail != "" {
			fmt.Fprintf(&b, "  Detail: %s\n", ev.Detail)
		}
		var cites []string
		for _, c := range ev.Cites {
			if c != nil && c.Asset != nil {
				cites = append(cites, string(c.Asset.AssetType())+" "+c.Asset.Key())
			}
		}
		if len(cites) > 0 {
			fmt.Fprintf(&b, "  Seen on: %s\n", strings.Join(cites, "; "))
		}
	}
	return b.String()
}

// signalDefinition returns the catalog's meaning of a signal: the
// related-domain use first, as admission widens scope, then owned-asset.
func signalDefinition(id string) (lens.OwnershipSignal, bool) {
	if s, ok := lens.LookupHorizontalSignal(id); ok {
		return s, true
	}
	return lens.LookupOwnershipSignal(id)
}
