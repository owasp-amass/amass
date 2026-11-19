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
	id := ScopeExpansionID("org-1", "FQDN", "acme.com")
	if !strings.HasPrefix(id, ScopeExpansionPrefix) {
		t.Errorf("id %q lacks the %q prefix", id, ScopeExpansionPrefix)
	}
	if id != ScopeExpansionID("org-1", "FQDN", "acme.com") {
		t.Error("id is not stable")
	}
	if id == ScopeExpansionID("org-1", "FQDN", "acme.net") {
		t.Error("different assets must get different ids")
	}
	// The empty asset type defaults to FQDN, so it yields the same id.
	if id != ScopeExpansionID("org-1", "", "acme.com") {
		t.Error("empty asset type should default to FQDN")
	}
	// A different asset type for the same key is a different expansion.
	if id == ScopeExpansionID("org-1", "Netblock", "acme.com") {
		t.Error("different asset types must get different ids")
	}
}

func TestRecordAndReadScopeExpansions(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "ai-review.jsonl")}

	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Org: "Acme", Asset: "acme.com",
		Confidence: 93, SignalIDs: []string{"shared-registrant-org", "cert-subject-org"},
		Status: ProposalApplied}); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Org: "Acme", Asset: "acme.net",
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
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Asset: "acme.net",
		Status: ProposalRetracted, Reviewer: "amass-ai (re-check)"}); err != nil {
		t.Fatal(err)
	}
	applied, err = j.AppliedScopeExpansions()
	if err != nil {
		t.Fatal(err)
	}
	if len(applied) != 1 || applied[0].Asset != "acme.com" {
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
		t.Error("a missing asset should be rejected")
	}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Asset: "x.com", Status: "nonsense"}); err == nil {
		t.Error("an invalid status should be rejected")
	}
}
