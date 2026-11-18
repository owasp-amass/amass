// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestScopeExpansionID(t *testing.T) {
	id := ScopeExpansionID("org-1", "acme.com")
	if !strings.HasPrefix(id, ScopeExpansionPrefix) {
		t.Errorf("id %q lacks the %q prefix", id, ScopeExpansionPrefix)
	}
	if id != ScopeExpansionID("org-1", "acme.com") {
		t.Error("id is not stable")
	}
	if id == ScopeExpansionID("org-1", "acme.net") {
		t.Error("different domains must get different ids")
	}
}

func TestRecordAndReadScopeExpansions(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "ai-review.jsonl")}

	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Org: "Acme", Domain: "acme.com",
		Confidence: 93, SignalIDs: []string{"shared-registrant-org", "cert-subject-org"},
		Status: ProposalApplied}); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Org: "Acme", Domain: "acme.net",
		Confidence: 70, SignalIDs: []string{"shared-registrant-org"}, Status: ProposalApplied}); err != nil {
		t.Fatal(err)
	}

	applied, err := j.AppliedScopeExpansions()
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied = %d, want 2", len(applied))
	}

	// Reconsidering acme.net retracts it: the latest record wins, so it drops
	// out of the applied set while acme.com stays.
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Domain: "acme.net",
		Status: ProposalRetracted, Reviewer: "amass-ai (re-check)"}); err != nil {
		t.Fatal(err)
	}
	applied, err = j.AppliedScopeExpansions()
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Domain != "acme.com" {
		t.Errorf("after retract, applied = %+v, want only acme.com", applied)
	}

	all, err := j.ScopeExpansions()
	if err != nil {
		t.Fatal(err)
	}
	if len(all) != 2 {
		t.Errorf("ScopeExpansions should keep one record per id, got %d", len(all))
	}
}

func TestRecordScopeExpansionValidates(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "ai-review.jsonl")}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Status: ProposalApplied}); err == nil {
		t.Error("a missing domain should be rejected")
	}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Domain: "x.com", Status: "nonsense"}); err == nil {
		t.Error("an invalid status should be rejected")
	}
}
