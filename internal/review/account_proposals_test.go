// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamacct "github.com/owasp-amass/open-asset-model/account"
)

func sampleAccountsReport() lens.AccountsReport {
	return lens.AccountsReport{
		Owner:   "OWASP Foundation",
		OwnerID: "org-1",
		Accounts: []lens.AccountEntry{
			{Platform: "GitHub", Type: "code", Handle: "owasp", URL: "https://github.com/owasp", URLID: "u1"},
			{Platform: "X", Type: "social", Handle: "owaspuniv", URL: "https://twitter.com/owaspuniv", URLID: "u2"},
		},
	}
}

func TestAccountProposals(t *testing.T) {
	ps := AccountProposals(sampleAccountsReport())
	if len(ps) != 2 {
		t.Fatalf("proposals = %+v", ps)
	}
	gh := ps[0]
	if gh.Platform != "GitHub" || gh.Handle != "owasp" || gh.OwnerID != "org-1" ||
		gh.EvidenceID != "u1" || gh.Status != ProposalPending {
		t.Errorf("github proposal = %+v", gh)
	}
	// The ID is stable and handle-case-insensitive.
	if gh.ID != AccountProposalID("org-1", "github", "OWASP") {
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
	more := append(proposals, AccountProposal{ID: AccountProposalID("org-1", "linkedin", "owasp-university"),
		Owner: "OWASP Foundation", OwnerID: "org-1", Platform: "LinkedIn", Handle: "owasp-university",
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

// fakeApplier is an in-memory AccountApplier/Deleter for testing ApplyAccount.
type fakeApplier struct {
	assets  map[string]oam.Asset
	edges   map[string]*dbt.Edge
	deleted map[string]bool
	n       int
}

func newFakeApplier() *fakeApplier {
	return &fakeApplier{assets: map[string]oam.Asset{}, edges: map[string]*dbt.Edge{}, deleted: map[string]bool{}}
}

func (f *fakeApplier) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	return &dbt.Entity{ID: id}, nil
}

func (f *fakeApplier) CreateAsset(_ context.Context, a oam.Asset) (*dbt.Entity, error) {
	f.n++
	id := fmt.Sprintf("asset-%d", f.n)
	f.assets[id] = a
	return &dbt.Entity{ID: id, Asset: a}, nil
}

func (f *fakeApplier) CreateEdge(_ context.Context, e *dbt.Edge) (*dbt.Edge, error) {
	f.n++
	e.ID = fmt.Sprintf("edge-%d", f.n)
	f.edges[e.ID] = e
	return e, nil
}

func (f *fakeApplier) CreateEntityProperty(_ context.Context, _ *dbt.Entity, _ oam.Property) (*dbt.EntityTag, error) {
	return &dbt.EntityTag{}, nil
}

func (f *fakeApplier) CreateEdgeProperty(_ context.Context, _ *dbt.Edge, _ oam.Property) (*dbt.EdgeTag, error) {
	return &dbt.EdgeTag{}, nil
}

func (f *fakeApplier) DeleteEdge(_ context.Context, id string) error {
	f.deleted[id] = true
	return nil
}

func TestApplyAccount(t *testing.T) {
	w := newFakeApplier()
	p := AccountProposal{ID: "acct-1", Owner: "OWASP Foundation", OwnerID: "org-1", Platform: "GitHub",
		AccountType: "code", Handle: "owasp", EvidenceURL: "https://github.com/owasp", Confidence: 90}

	edgeID, err := ApplyAccount(context.Background(), w, p)
	if err != nil {
		t.Fatal(err)
	}
	if edgeID == "" || len(w.assets) != 1 || len(w.edges) != 1 {
		t.Fatalf("apply did not create the account and edge: assets=%d edges=%d", len(w.assets), len(w.edges))
	}
	var acct *oamacct.Account
	for _, a := range w.assets {
		acct, _ = a.(*oamacct.Account)
	}
	if acct == nil || acct.Username != "owasp" || acct.Type != "code" || acct.ID != "github:owasp" {
		t.Errorf("account asset = %+v", acct)
	}
}

func TestAccountLifecycle(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	p := AccountProposals(sampleAccountsReport())[0] // GitHub
	if _, err := j.SubmitAccounts([]AccountProposal{p}); err != nil {
		t.Fatal(err)
	}

	got, err := j.PendingAccount(p.ID)
	if err != nil || got.Handle != "owasp" {
		t.Fatalf("pending = %+v err=%v", got, err)
	}

	if err := j.RecordAccount(AccountOutcome{ProposalID: p.ID, Status: ProposalApplied, Reviewer: "jeff",
		EdgeID: "edge-9"}); err != nil {
		t.Fatal(err)
	}
	// No longer pending once applied.
	if _, err := j.PendingAccount(p.ID); err == nil {
		t.Error("an applied proposal should not be pending")
	}
	ap, edge, err := j.AppliedAccount(p.ID)
	if err != nil || edge != "edge-9" || ap.Platform != "GitHub" {
		t.Errorf("applied = %+v edge=%q err=%v", ap, edge, err)
	}

	// Retraction is recorded and clears the applied state.
	if err := j.RecordAccount(AccountOutcome{ProposalID: p.ID, Status: ProposalRetracted, Reviewer: "jeff"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := j.AppliedAccount(p.ID); err == nil {
		t.Error("a retracted proposal should not be applied")
	}
}
