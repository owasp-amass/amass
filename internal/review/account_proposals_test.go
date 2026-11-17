// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
)

func sampleAccountsReport() lens.AccountsReport {
	return lens.AccountsReport{
		Owner:   "Colgate University",
		OwnerID: "org-1",
		Accounts: []lens.AccountEntry{
			{Platform: "GitHub", Type: "code", Handle: "colgate", URL: "https://github.com/colgate", URLID: "u1"},
			{Platform: "X", Type: "social", Handle: "colgateuniv", URL: "https://twitter.com/colgateuniv", URLID: "u2"},
		},
	}
}

func TestAccountProposals(t *testing.T) {
	ps := AccountProposals(sampleAccountsReport())
	if len(ps) != 2 {
		t.Fatalf("proposals = %+v", ps)
	}
	gh := ps[0]
	if gh.Platform != "GitHub" || gh.Handle != "colgate" || gh.OwnerID != "org-1" ||
		gh.EvidenceID != "u1" || gh.Status != ProposalPending {
		t.Errorf("github proposal = %+v", gh)
	}
	// The ID is stable and handle-case-insensitive.
	if gh.ID != AccountProposalID("org-1", "github", "COLGATE") {
		t.Errorf("unstable proposal ID: %s", gh.ID)
	}
	// No owner, no proposals.
	if ps := AccountProposals(lens.AccountsReport{Accounts: sampleAccountsReport().Accounts}); ps != nil {
		t.Errorf("expected no proposals without an owner, got %+v", ps)
	}
}

func TestSubmitAccountsDedup(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	proposals := AccountProposals(sampleAccountsReport())

	added, err := j.SubmitAccounts(proposals)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 2 {
		t.Fatalf("first submit added %d, want 2", len(added))
	}

	// Submitting the same proposals again adds nothing.
	added, err = j.SubmitAccounts(proposals)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 0 {
		t.Errorf("second submit added %d, want 0", len(added))
	}

	// A new account is added on top.
	more := append(proposals, AccountProposal{ID: AccountProposalID("org-1", "linkedin", "colgate-university"),
		Owner: "Colgate University", OwnerID: "org-1", Platform: "LinkedIn", Handle: "colgate-university",
		Status: ProposalPending})
	added, err = j.SubmitAccounts(more)
	if err != nil {
		t.Fatal(err)
	}
	if len(added) != 1 || added[0].Platform != "LinkedIn" {
		t.Errorf("third submit = %+v", added)
	}
}

func TestSubmitAccountsRejectsIncomplete(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if _, err := j.SubmitAccounts([]AccountProposal{{Platform: "GitHub", Handle: "x"}}); err == nil {
		t.Error("expected an error for a proposal with no ID or owner")
	}
}
