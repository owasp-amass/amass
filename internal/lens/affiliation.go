// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// LensAffiliation asks which other organizations a domain or organization is
// affiliated with: distinct organizations tied to it by shared attributes — a
// shared phone, a shared contact person, a shared funder or a shared address —
// each a cited signal, combined into a confidence. The answer is computed from
// stored relationships; nothing is written (conclusions persist only through
// review, ai-design-principles.md principle 10).
const LensAffiliation = "affiliation"

var affiliationLens = SubjectLens{
	Name:    LensAffiliation,
	Command: "affiliation",
	Description: "Show the organizations a domain or organization is affiliated with — tied by a shared phone, " +
		"person, funder or address — with the signals and a confidence. Read-only",
	Examples: []string{"Which organizations are affiliated with <organization>?",
		"Who shares a phone, office or backer with <domain>'s organization?",
		"What companies are connected to <organization> through people or funders?"},
	Find: func(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
		opts Options) (Report, error) {
		return FindAffiliation(ctx, g, schema, root, opts.Limits)
	},
}

// affiliationSignal is one shared-attribute signal and its weight.
type affiliationSignal struct {
	Key       string  `json:"key"`
	Weight    float64 `json:"weight"`
	Rationale string  `json:"rationale"`
}

var loadAffiliationSignals = sync.OnceValue(func() map[string]affiliationSignal {
	var cat struct {
		Signals []affiliationSignal `json:"signals"`
	}
	if err := json.Unmarshal(semantics.File("affiliation_signals.json"), &cat); err != nil {
		panic("affiliation_signals.json: " + err.Error())
	}
	out := make(map[string]affiliationSignal, len(cat.Signals))
	for _, s := range cat.Signals {
		out[s.Key] = s
	}
	return out
})

// AffiliatedOrg is a candidate affiliate with the signals that tie it and the
// combined confidence.
type AffiliatedOrg struct {
	Name       string   `json:"name"`
	ID         string   `json:"id"`
	Signals    []string `json:"signals"`
	Confidence int      `json:"confidence"`
}

// AffiliationReport is the result of the affiliation lens.
type AffiliationReport struct {
	lensBase
	Candidates []AffiliatedOrg `json:"candidates"`
}

// anchor is a shared attribute of the subject that, when another organization
// shares it, is a signal of affiliation.
type anchor struct {
	asset  graph.Asset
	signal string
	label  string
}

// FindAffiliation computes the organizations affiliated with a domain or
// organization from shared phones, people, funders and addresses. It reads only.
func FindAffiliation(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset,
	limits LensLimits) (AffiliationReport, error) {
	g = graph.Cached(g)
	var out AffiliationReport
	s, err := newScope(ctx, g, schema, root, limits, LensAffiliation)
	if err != nil {
		return out, err
	}

	subjects := append([]graph.Asset(nil), s.owners...)
	if root.Type == "Organization" {
		subjects = append(subjects, root)
	}
	subjectID := map[string]bool{}
	for _, o := range subjects {
		subjectID[o.ID] = true
	}

	// candidate org ID -> signal key -> evidence label (first seen).
	cands := map[string]*struct {
		name    string
		signals map[string]string
	}{}
	add := func(org graph.Asset, signal, evidence string) {
		if subjectID[org.ID] {
			return
		}
		c := cands[org.ID]
		if c == nil {
			c = &struct {
				name    string
				signals map[string]string
			}{name: graph.AssetLabel(org), signals: map[string]string{}}
			cands[org.ID] = c
		}
		if _, ok := c.signals[signal]; !ok {
			c.signals[signal] = evidence
		}
	}

	for _, org := range subjects {
		if s.spent() {
			break
		}
		anchors, err := s.orgAnchors(org)
		if err != nil {
			return out, err
		}
		for _, an := range anchors {
			if s.spent() {
				break
			}
			others, err := s.orgsSharing(an)
			if err != nil {
				return out, err
			}
			for _, o := range others {
				add(o, an.signal, an.label)
			}
		}
	}

	sig := loadAffiliationSignals()
	for id, c := range cands {
		var labels []string
		weights := make([]float64, 0, len(c.signals))
		for _, key := range []string{"shared_phone", "shared_person", "shared_funder", "shared_address"} {
			ev, ok := c.signals[key]
			if !ok {
				continue
			}
			weights = append(weights, sig[key].Weight)
			labels = append(labels, signalLabel(key)+": "+ev)
		}
		out.Candidates = append(out.Candidates, AffiliatedOrg{
			Name: c.name, ID: id, Signals: labels, Confidence: int(noisyOr(weights)*100 + 0.5),
		})
	}
	sort.SliceStable(out.Candidates, func(i, j int) bool {
		if out.Candidates[i].Confidence != out.Candidates[j].Confidence {
			return out.Candidates[i].Confidence > out.Candidates[j].Confidence
		}
		return out.Candidates[i].Name < out.Candidates[j].Name
	})
	out.lensBase = s.base()
	return out, nil
}

// orgAnchors gathers the subject organization's shared-attribute anchors: the
// phones, people, addresses on its contact records and members, and the funders
// of transfers it received.
func (s *scope) orgAnchors(org graph.Asset) ([]anchor, error) {
	steps, err := s.w.steps(org)
	if err != nil {
		return nil, err
	}

	var out []anchor
	for _, st := range steps {
		switch {
		case !st.forward && st.other.Type == "ContactRecord":
			crs, err := s.w.steps(st.other)
			if err != nil {
				return nil, err
			}
			for _, cs := range crs {
				if !cs.forward {
					continue
				}
				switch cs.other.Type {
				case "Phone":
					out = append(out, anchor{cs.other, "shared_phone", phoneLabel(cs.other)})
				case "Location":
					out = append(out, anchor{cs.other, "shared_address", locationLabel(cs.other)})
				case "Person":
					out = append(out, anchor{cs.other, "shared_person", personLabel(cs.other)})
				}
			}
		case st.forward && st.other.Type == "Person": // a member
			out = append(out, anchor{st.other, "shared_person", personLabel(st.other)})
		case st.forward && st.other.Type == "Account": // funders of received transfers
			funders, err := s.accountFunders(st.other)
			if err != nil {
				return nil, err
			}
			out = append(out, funders...)
		}
	}
	return out, nil
}

// accountFunders returns the funding organizations named on the transfers an
// account received.
func (s *scope) accountFunders(account graph.Asset) ([]anchor, error) {
	steps, err := s.w.steps(account)
	if err != nil {
		return nil, err
	}

	var out []anchor
	for _, st := range steps {
		if st.forward || st.other.Type != "FundsTransfer" {
			continue
		}
		fts, err := s.w.steps(st.other)
		if err != nil {
			return nil, err
		}
		for _, fs := range fts {
			if fs.forward && fs.other.Type == "Organization" {
				out = append(out, anchor{fs.other, "shared_funder", graph.AssetLabel(fs.other)})
			}
		}
	}
	return out, nil
}

// orgsSharing returns the organizations, other than the subject, that share an
// anchor attribute with it.
func (s *scope) orgsSharing(an anchor) ([]graph.Asset, error) {
	switch an.signal {
	case "shared_phone", "shared_address":
		return s.orgsViaContactRecord(an.asset)
	case "shared_person":
		orgs, err := s.orgsViaContactRecord(an.asset)
		if err != nil {
			return nil, err
		}
		// A person may also be a member of an organization directly.
		steps, err := s.w.steps(an.asset)
		if err != nil {
			return nil, err
		}
		for _, st := range steps {
			if !st.forward && st.other.Type == "Organization" {
				orgs = append(orgs, st.other)
			}
		}
		return orgs, nil
	case "shared_funder":
		return s.orgsFundedBy(an.asset)
	}
	return nil, nil
}

// orgsViaContactRecord returns the organizations whose contact records point at
// an attribute asset (a phone, address or person).
func (s *scope) orgsViaContactRecord(attr graph.Asset) ([]graph.Asset, error) {
	steps, err := s.w.steps(attr)
	if err != nil {
		return nil, err
	}

	var out []graph.Asset
	for _, st := range steps {
		if st.forward || st.other.Type != "ContactRecord" {
			continue
		}
		crs, err := s.w.steps(st.other)
		if err != nil {
			return nil, err
		}
		for _, cs := range crs {
			if cs.forward && cs.other.Type == "Organization" {
				out = append(out, cs.other)
			}
		}
	}
	return out, nil
}

// orgsFundedBy returns the organizations that received a transfer from a funder.
func (s *scope) orgsFundedBy(funder graph.Asset) ([]graph.Asset, error) {
	steps, err := s.w.steps(funder)
	if err != nil {
		return nil, err
	}

	var out []graph.Asset
	for _, st := range steps {
		if st.forward || st.other.Type != "FundsTransfer" {
			continue
		}
		fts, err := s.w.steps(st.other)
		if err != nil {
			return nil, err
		}
		for _, fs := range fts {
			if !fs.forward || fs.other.Type != "Account" {
				continue
			}
			accs, err := s.w.steps(fs.other)
			if err != nil {
				return nil, err
			}
			for _, as := range accs {
				if !as.forward && as.other.Type == "Organization" {
					out = append(out, as.other)
				}
			}
		}
	}
	return out, nil
}

// noisyOr combines independent signal weights: 1 - product of (1 - weight).
func noisyOr(weights []float64) float64 {
	prod := 1.0
	for _, w := range weights {
		prod *= (1 - w)
	}
	return 1 - prod
}

// signalLabel is the human name of a signal key.
func signalLabel(key string) string {
	switch key {
	case "shared_phone":
		return "shared phone"
	case "shared_person":
		return "shared person"
	case "shared_funder":
		return "shared funder"
	case "shared_address":
		return "shared address"
	}
	return key
}

// Text implements Report.
func (r AffiliationReport) Text() string {
	var b strings.Builder
	subject := graph.AssetLabel(r.Root)
	if len(r.Owners) > 0 {
		subject += " and " + strings.Join(r.Owners, ", ")
	}

	fmt.Fprintf(&b, "Affiliations of %s: %d candidate(s) (%d reads).\n", subject, len(r.Candidates), r.Reads)
	if len(r.Candidates) == 0 {
		b.WriteString("\nNo other organization shares a phone, person, funder or address with it.\n")
		return b.String()
	}

	b.WriteString("\n")
	for _, c := range r.Candidates {
		fmt.Fprintf(&b, "  %s (confidence %d%%)\n", c.Name, c.Confidence)
		for _, s := range c.Signals {
			fmt.Fprintf(&b, "    - %s\n", s)
		}
	}

	b.WriteString("\nThese are computed from shared attributes, not stated ownership; a shared attribute is " +
		"evidence of a tie, not proof. Review before relying on one." + r.partialNote() + "\n")
	return b.String()
}

// Facts implements Report.
func (r AffiliationReport) Facts() []string {
	out := make([]string, 0, len(r.Candidates))
	for _, c := range r.Candidates {
		out = append(out, fmt.Sprintf("affiliate %s (%d%%)", c.Name, c.Confidence))
	}
	return out
}
