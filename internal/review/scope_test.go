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
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}

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
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Status: ProposalApplied}); err == nil {
		t.Error("a missing asset should be rejected")
	}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Asset: "x.com", Status: "nonsense"}); err == nil {
		t.Error("an invalid status should be rejected")
	}
}

// Only a person's rejection or retraction keeps an expansion out of later
// runs; the reevaluation sweep's does not, as the evidence may return. A
// person's approval is kept apart from automatic ones.
func TestDeclinedScopeExpansions(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	for _, e := range []ScopeExpansion{
		{OrgID: "org-1", Asset: "acme.com", Status: ProposalApplied, Reviewer: "amass-ai (model ollama/qwen3:30b)"},
		{OrgID: "org-1", Asset: "acme.com", Status: ProposalRetracted, Reviewer: "jeff"},
		{OrgID: "org-1", Asset: "acme.net", Status: ProposalApplied, Reviewer: AutomaticReviewer},
		{OrgID: "org-1", Asset: "acme.net", Status: ProposalRetracted, Reviewer: RecheckReviewer},
		{OrgID: "org-1", Asset: "acme.org", Status: ProposalPending},
		{OrgID: "org-1", Asset: "acme.org", Status: ProposalRejected, Reviewer: "jeff"},
		{OrgID: "org-1", Asset: "acme.io", Status: ProposalPending},
		{OrgID: "org-1", Asset: "acme.io", Status: ProposalApplied, Reviewer: "jeff"},
	} {
		if err := j.RecordScopeExpansion(e); err != nil {
			t.Fatal(err)
		}
	}

	r, err := j.DeclinedScopeExpansions()
	if err != nil {
		t.Fatal(err)
	}
	if !r[ScopeExpansionID("org-1", "", "acme.com")] || !r[ScopeExpansionID("org-1", "", "acme.org")] ||
		r[ScopeExpansionID("org-1", "", "acme.net")] || len(r) != 2 {
		t.Errorf("declined = %v", r)
	}
	approved, err := j.ApprovedScopeExpansions()
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := approved[ScopeExpansionID("org-1", "", "acme.io")]; !ok || len(approved) != 1 {
		t.Errorf("approved = %v", approved)
	}
	if !IsScopeExpansion(ScopeExpansionID("org-1", "", "acme.com")) || IsScopeExpansion("own-1234") {
		t.Error("IsScopeExpansion")
	}
}

// A person approves or rejects a pending expansion; nothing else can be
// decided that way.
func TestDecideScopeExpansion(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	for _, asset := range []string{"acme.org", "acme.io"} {
		if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "org-1", Org: "Acme", Asset: asset,
			Confidence: 60, Signals: []string{"same favicon"}, Status: ProposalPending}); err != nil {
			t.Fatal(err)
		}
	}
	orgID := ScopeExpansionID("org-1", "", "acme.org")
	ioID := ScopeExpansionID("org-1", "", "acme.io")

	if pending, err := j.PendingScopeExpansions(); err != nil || len(pending) != 2 {
		t.Fatalf("pending = %v, %v", pending, err)
	}
	if _, err := DecideScopeExpansion(j, orgID, ProposalApplied, AutomaticReviewer); err == nil {
		t.Error("an amass-ai reviewer decided a pending expansion")
	}
	if _, err := DecideScopeExpansion(j, orgID, ProposalRetracted, "jeff"); err == nil {
		t.Error("a pending expansion was retracted")
	}

	e, err := DecideScopeExpansion(j, orgID, ProposalApplied, "jeff")
	if err != nil || e.Status != ProposalApplied || e.Confidence != 60 || len(e.Signals) != 1 {
		t.Fatalf("approve = %+v, %v", e, err)
	}
	if _, err := DecideScopeExpansion(j, orgID, ProposalRejected, "jeff"); err == nil {
		t.Error("an approved expansion was decided again")
	}
	if _, err := DecideScopeExpansion(j, ioID, ProposalRejected, "jeff"); err != nil {
		t.Fatal(err)
	}

	if pending, _ := j.PendingScopeExpansions(); len(pending) != 0 {
		t.Errorf("still pending: %v", pending)
	}
	if text := FormatScopeExpansions([]ScopeExpansion{e}); !strings.Contains(text, "widen Acme's scope to FQDN acme.org") ||
		!strings.Contains(text, "by jeff") {
		t.Errorf("listing:\n%s", text)
	}
}

// A model's answer on a pending expansion is kept when a later run proposes
// it again on the same signals without asking the model, and dropped when
// the signals change or a person decides.
func TestScopeAdviceIsKept(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	advice := &ScopeAdvice{Model: "model test", Decision: ScopeAdviceReject, Confidence: 93}
	for _, e := range []ScopeExpansion{
		{OrgID: "o", Asset: "a.example", SignalIDs: []string{"x", "y"}, Status: ProposalPending, Advice: advice},
		{OrgID: "o", Asset: "a.example", SignalIDs: []string{"y", "x"}, Status: ProposalPending},
		{OrgID: "o", Asset: "b.example", SignalIDs: []string{"x"}, Status: ProposalPending, Advice: advice},
		{OrgID: "o", Asset: "b.example", SignalIDs: []string{"x", "z"}, Status: ProposalPending},
		{OrgID: "o", Asset: "c.example", SignalIDs: []string{"x"}, Status: ProposalPending, Advice: advice},
		{OrgID: "o", Asset: "c.example", SignalIDs: []string{"x"}, Status: ProposalRejected, Reviewer: "jeff"},
		{OrgID: "o", Asset: "c.example", SignalIDs: []string{"x"}, Status: ProposalPending},
	} {
		if err := j.RecordScopeExpansion(e); err != nil {
			t.Fatal(err)
		}
	}

	all, err := j.ScopeExpansions()
	if err != nil || len(all) != 3 {
		t.Fatalf("expansions = %+v, %v", all, err)
	}
	for _, e := range all {
		if kept := e.Advice != nil; kept != (e.Asset == "a.example") {
			t.Errorf("%s: advice %+v", e.Asset, e.Advice)
		}
	}
}
