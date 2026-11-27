// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

func TestRecheckScopeExpansions(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}

	witness := func(domain string) []graph.WitnessEdge {
		return []graph.WitnessEdge{{FromID: "dr-" + domain, Label: "registrant_contact", ToID: "cr-1", To: domain}}
	}
	seed := func(domain, reviewer string) {
		if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Org: "Acme", Asset: domain,
			Confidence: 80, SignalIDs: []string{"shared-registrant-org"}, Witness: witness(domain),
			Status: ProposalApplied, Reviewer: reviewer}); err != nil {
			t.Fatal(err)
		}
	}
	seed("acme.com", AutomaticReviewer) // AI, evidence stays → untouched
	seed("acme.net", AutomaticReviewer) // AI, evidence gone → retracted
	seed("acme.org", "jeff")            // human, evidence gone → reopened for review

	// The witness is "gone" for acme.net and acme.org.
	gone := map[string]bool{"acme.net": true, "acme.org": true}
	check := func(w []graph.WitnessEdge) (string, error) {
		if len(w) > 0 && gone[w[0].To] {
			return "witness gone", nil
		}
		return "", nil
	}

	res, err := recheckScopeExpansions(context.Background(), j, check)
	if err != nil {
		t.Fatal(err)
	}
	if res.Checked != 3 {
		t.Errorf("checked = %d, want 3", res.Checked)
	}
	if len(res.Retracted) != 1 || res.Retracted[0].Asset != "acme.net" {
		t.Errorf("retracted = %+v, want [acme.net]", res.Retracted)
	}
	if len(res.Flagged) != 1 || res.Flagged[0].Asset != "acme.org" {
		t.Errorf("flagged = %+v, want [acme.org]", res.Flagged)
	}

	// After the re-check: the AI expansion whose evidence vanished is no longer
	// applied; the one whose evidence stayed is; the human one is reopened
	// (pending), so it is not applied either but was not retracted.
	applied, err := j.AppliedScopeExpansions()
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Asset != "acme.com" {
		t.Errorf("applied after re-check = %+v, want only acme.com", applied)
	}
}

func TestScopeExpansionRedecidable(t *testing.T) {
	if !ScopeExpansionRedecidable(ProposalPending, "") {
		t.Error("a pending expansion is redecidable")
	}
	if !ScopeExpansionRedecidable(ProposalRetracted, RecheckReviewer) {
		t.Error("a re-check retraction is redecidable")
	}
	if ScopeExpansionRedecidable(ProposalRetracted, "jeff") {
		t.Error("a person's retraction is sticky, not redecidable")
	}
	if ScopeExpansionRedecidable(ProposalApplied, AutomaticReviewer) {
		t.Error("an applied expansion is not awaiting a fresh decision")
	}
}
