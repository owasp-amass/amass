// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// ScopeExpansionPrefix prefixes the id of a scope-expansion record, so it is
// never mistaken for another kind of proposal.
const ScopeExpansionPrefix = "hdom-"

// DefaultScopeAssetType is the asset type a scope expansion names when none is
// recorded, so the original horizontal domain records (which stored no type)
// keep meaning an FQDN.
const DefaultScopeAssetType = "FQDN"

// ScopeExpansion records an asset the scored correlation added to, or proposed
// for, an enumeration's scope, with the evidence behind it. It is asset-agnostic
// — a registered domain (FQDN, the default), a netblock, or an autonomous system
// — identified by AssetType and the asset's key (Asset). It makes a runtime
// scope change auditable and reversible: the reevaluation sweep re-tests an
// applied expansion as the enumeration brings in new evidence and retracts it if
// the evidence no longer supports it, so scope is never silently or permanently
// grown on a stale conclusion (ai-design-principles.md, principles 9 & 13). An
// applied expansion was added to scope during the run; a pending one is
// corroboration-only and waits for a person; a retracted one was reconsidered
// and removed.
type ScopeExpansion struct {
	ID    string `json:"id"`
	OrgID string `json:"org_id"`
	Org   string `json:"org"`
	// AssetType is the OAM type of the scoped asset ("FQDN", "Netblock",
	// "AutonomousSystem"); empty means FQDN for the original domain records.
	AssetType  string              `json:"asset_type,omitempty"`
	Asset      string              `json:"asset"`
	Confidence int                 `json:"confidence"`
	Signals    []string            `json:"signals,omitempty"`
	SignalIDs  []string            `json:"signal_ids,omitempty"`
	Witness    []graph.WitnessEdge `json:"witness,omitempty"`
	Status     string              `json:"status"`
	Reviewer   string              `json:"reviewer,omitempty"`
	// DecidedConfidence is the confidence of the model or classifier that
	// applied the expansion (0..100); Confidence is the signals' score.
	DecidedConfidence int `json:"decided_confidence,omitempty"`
	// Advice is the model's answer on a pending expansion it did not apply:
	// it rejected the asset, or would admit it below the policy's
	// confidence. A person still decides.
	Advice *ScopeAdvice `json:"advice,omitempty"`
	At     time.Time    `json:"at"`
}

// ScopeAdvice is a model's answer on a scope expansion.
type ScopeAdvice struct {
	// Model is the decider's name ("model claude-sonnet-4-5").
	Model string `json:"model"`
	// Decision is ScopeAdviceAdmit or ScopeAdviceReject.
	Decision   string `json:"decision"`
	Confidence int    `json:"confidence"`
	Reason     string `json:"reason,omitempty"`
}

// The decisions a model's ScopeAdvice gives.
const (
	ScopeAdviceAdmit  = "admit"
	ScopeAdviceReject = "reject"
)

// Kind returns the scoped asset's OAM type, defaulting to FQDN.
func (e ScopeExpansion) Kind() string {
	if e.AssetType == "" {
		return DefaultScopeAssetType
	}
	return e.AssetType
}

// ScopeExpansionID is a stable identifier for an organization's scope expansion
// of one asset, so the same expansion is recorded once and a reconsidered one is
// recognized rather than duplicated. An empty assetType is the FQDN default.
func ScopeExpansionID(orgID, assetType, asset string) string {
	if assetType == "" {
		assetType = DefaultScopeAssetType
	}
	sum := sha256.Sum256([]byte(orgID + "\x00" + assetType + "\x00" + asset))
	return ScopeExpansionPrefix + hex.EncodeToString(sum[:8])
}

// RecordScopeExpansion appends a scope-expansion record — applied, pending
// review, rejected or retracted — filling the id and timestamp when unset.
func (j *Journal) RecordScopeExpansion(e ScopeExpansion) error {
	if e.OrgID == "" || e.Asset == "" {
		return errors.New("scope expansion needs an organization and an asset")
	}
	if e.Status != ProposalApplied && e.Status != ProposalPending && e.Status != ProposalRetracted &&
		e.Status != ProposalRejected {
		return fmt.Errorf("invalid scope-expansion status %q", e.Status)
	}
	if e.ID == "" {
		e.ID = ScopeExpansionID(e.OrgID, e.AssetType, e.Asset)
	}
	if e.At.IsZero() {
		e.At = time.Now().UTC()
	}

	return j.append("scope_expansion", e)
}

// ScopeExpansions returns the latest record for each scope expansion, in the
// order the expansions were first recorded, so applied and reconsidered
// expansions can be listed and re-checked.
func (j *Journal) ScopeExpansions() ([]ScopeExpansion, error) {
	hist, err := j.History()
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	latest := map[string]ScopeExpansion{}
	var order []string
	for _, raw := range hist {
		var head struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(raw, &head) != nil || head.Kind != "scope_expansion" {
			continue
		}
		var e ScopeExpansion
		if json.Unmarshal(head.Data, &e) != nil || e.ID == "" {
			continue
		}
		prev, seen := latest[e.ID]
		if !seen {
			order = append(order, e.ID)
		}
		if keepsAdvice(prev, e) {
			e.Advice = prev.Advice
		}
		latest[e.ID] = e
	}

	out := make([]ScopeExpansion, 0, len(order))
	for _, id := range order {
		out = append(out, latest[id])
	}

	return out, nil
}

// keepsAdvice reports whether a pending record with no model answer keeps
// the answer of the pending record before it: a later run proposed it again
// on the same signals but did not ask the model (it was stopped, say).
func keepsAdvice(prev, e ScopeExpansion) bool {
	if prev.Advice == nil || e.Advice != nil || prev.Status != ProposalPending || e.Status != ProposalPending {
		return false
	}
	a, b := slices.Clone(prev.SignalIDs), slices.Clone(e.SignalIDs)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}

// IsScopeExpansion reports whether id names a scope-expansion record.
func IsScopeExpansion(id string) bool {
	return strings.HasPrefix(id, ScopeExpansionPrefix)
}

// AppliedScopeExpansions returns the expansions whose latest record is applied —
// the ones currently in scope — for the reevaluation sweep.
func (j *Journal) AppliedScopeExpansions() ([]ScopeExpansion, error) {
	all, err := j.ScopeExpansions()
	if err != nil {
		return nil, err
	}

	var out []ScopeExpansion
	for _, e := range all {
		if e.Status == ProposalApplied {
			out = append(out, e)
		}
	}

	return out, nil
}
