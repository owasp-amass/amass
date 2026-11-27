// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// A person can undo a scope expansion the model or the rules applied, and no
// later run widens its scope to that domain again.
func TestRetractScopeExpansion(t *testing.T) {
	path := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	j := path
	if err := j.RecordScopeExpansion(review.ScopeExpansion{OrgID: "org-1", Org: "Acme", Asset: "acme-arts.org",
		Status: review.ProposalApplied, Reviewer: "amass-ai (model ollama/qwen3:30b)"}); err != nil {
		t.Fatal(err)
	}
	id := review.ScopeExpansionID("org-1", "", "acme-arts.org")

	text, err := Decide(context.Background(), oamrepo.Adapter{}, path, DecisionRetract, id, "", "jeff", false)
	if err != nil || !strings.Contains(text, "acme-arts.org") {
		t.Fatalf("Decide = %q, %v", text, err)
	}
	if r, _ := j.DeclinedScopeExpansions(); !r[id] {
		t.Error("the retraction was not recorded as a person's")
	}

	if _, err := Decide(context.Background(), oamrepo.Adapter{}, path, DecisionRetract, id, "", "jeff", false); err == nil ||
		!strings.Contains(err.Error(), "not applied") {
		t.Errorf("retracting twice: %v", err)
	}
}

// A person approves or rejects a pending scope expansion, and pending ones are
// listed for review.
func TestDecidePendingScopeExpansion(t *testing.T) {
	path := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	j := path
	for _, asset := range []string{"acme-arts.org", "acme-shop.com"} {
		if err := j.RecordScopeExpansion(review.ScopeExpansion{OrgID: "org-1", Org: "Acme", Asset: asset,
			Confidence: 55, Signals: []string{"same favicon"}, Status: review.ProposalPending}); err != nil {
			t.Fatal(err)
		}
	}
	arts := review.ScopeExpansionID("org-1", "", "acme-arts.org")
	shop := review.ScopeExpansionID("org-1", "", "acme-shop.com")

	text, err := PendingProposalsText(path)
	if err != nil || !strings.Contains(text, "Scope expansions:") || !strings.Contains(text, "acme-shop.com") {
		t.Fatalf("pending = %q, %v", text, err)
	}
	if s, _ := PendingProposalsSummary(path); s.Expansions != 2 || s.Total != 2 {
		t.Errorf("summary = %+v", s)
	}

	if text, err = Decide(context.Background(), oamrepo.Adapter{}, path, DecisionApprove, arts, "", "jeff", false); err != nil ||
		!strings.Contains(text, "Approved") {
		t.Fatalf("approve = %q, %v", text, err)
	}
	if text, err = Decide(context.Background(), oamrepo.Adapter{}, path, DecisionReject, shop, "", "jeff", false); err != nil ||
		!strings.Contains(text, "Rejected") {
		t.Fatalf("reject = %q, %v", text, err)
	}

	if approved, _ := j.ApprovedScopeExpansions(); len(approved) != 1 {
		t.Errorf("approved = %v", approved)
	}
	if declined, _ := j.DeclinedScopeExpansions(); !declined[shop] {
		t.Errorf("declined = %v", declined)
	}
	if text, _ = PendingProposalsText(path); !strings.Contains(text, "No proposals are awaiting review") {
		t.Errorf("still pending:\n%s", text)
	}
}
