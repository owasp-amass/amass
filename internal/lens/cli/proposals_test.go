// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

type fakeOwnershipWriter struct {
	writes     []lens.ProposedEdge
	confidence int
}

func (f *fakeOwnershipWriter) ApplyOwnership(_ context.Context, e lens.ProposedEdge, confidence int) (string, bool, error) {
	f.writes = append(f.writes, e)
	f.confidence = confidence
	return "77", false, nil
}

func journalWithProposal(t *testing.T) (string, review.OwnershipProposal) {
	t.Helper()

	edge := lens.ProposedEdge{FromID: "1", FromType: "ContactRecord", From: "https://rdap.example/alumni",
		Label: "organization", RelationType: "SimpleRelation", ToID: "2", ToType: "Organization",
		To: "Synthetic University"}
	p := review.OwnershipProposal{ID: review.ProposalID(edge), Owner: "Synthetic University", OwnerID: "2",
		Asset: edge.From, AssetID: "1", AssetType: "ContactRecord", Edge: edge, Score: 0.9,
		Decision: lens.GapPropose, Signals: []string{"identity via phone"}}
	path := filepath.Join(t.TempDir(), "review.jsonl")
	if _, err := (&review.Journal{Path: path}).SubmitOwnership([]review.OwnershipProposal{p}); err != nil {
		t.Fatal(err)
	}

	return path, p
}

func TestApproveWritesOnceWithScoreAsConfidence(t *testing.T) {
	path, p := journalWithProposal(t)
	w := &fakeOwnershipWriter{}
	var out bytes.Buffer
	if err := approveProposal(context.Background(), w, path, p.ID, "", &out); err == nil {
		t.Error("approve without a reviewer was accepted")
	}
	if err := approveProposal(context.Background(), w, path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}
	if len(w.writes) != 1 || w.writes[0] != p.Edge || w.confidence != 90 {
		t.Errorf("writes = %+v at confidence %d", w.writes, w.confidence)
	}
	if !strings.Contains(out.String(), "Wrote edge 77") {
		t.Errorf("output = %q", out.String())
	}
	if err := approveProposal(context.Background(), w, path, p.ID, "jeff", &out); err == nil || len(w.writes) != 1 {
		t.Error("an applied proposal was written again")
	}

	out.Reset()
	if err := listProposals(path, "json", false, &out); err != nil || !strings.Contains(out.String(), "applied by jeff") {
		t.Errorf("listing = %q, %v", out.String(), err)
	}
}

func TestRejectWritesNothing(t *testing.T) {
	path, p := journalWithProposal(t)
	var out bytes.Buffer
	if err := rejectProposal(path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}

	w := &fakeOwnershipWriter{}
	if err := approveProposal(context.Background(), w, path, p.ID, "jeff", &out); err == nil || len(w.writes) != 0 {
		t.Error("a rejected proposal was approved")
	}
}

type fakeRetractor struct {
	edges []string
}

func (f *fakeRetractor) RetractOwnership(_ context.Context, edgeID string) (bool, error) {
	f.edges = append(f.edges, edgeID)
	return true, nil
}

func TestRetractRemovesAppliedEdgeAndBlocksRewrites(t *testing.T) {
	path, p := journalWithProposal(t)
	var out bytes.Buffer
	r := &fakeRetractor{}
	if err := retractProposal(context.Background(), r, path, p.ID, "jeff", &out); err == nil {
		t.Error("a pending proposal was retracted")
	}
	if err := approveProposal(context.Background(), &fakeOwnershipWriter{}, path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}
	if err := retractProposal(context.Background(), r, path, p.ID, "jeff", &out); err != nil {
		t.Fatal(err)
	}
	if len(r.edges) != 1 || r.edges[0] != "77" {
		t.Errorf("retracted edges = %v", r.edges)
	}

	state, err := (&review.Journal{Path: path}).OwnershipState()
	if err != nil || state[p.ID].Status != review.ProposalRetracted {
		t.Errorf("status = %+v, %v", state[p.ID], err)
	}
}

func TestPendingProposalsListsOnlyAwaitingDecision(t *testing.T) {
	path, p := journalWithProposal(t)

	var out bytes.Buffer
	if err := pendingProposals(path, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "awaiting review") || !strings.Contains(out.String(), p.Owner) {
		t.Errorf("pending listing omits the proposed item: %q", out.String())
	}

	// Once decided, the proposal must drop out of the pending view.
	if err := rejectProposal(path, p.ID, "jeff", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	out.Reset()
	if err := pendingProposals(path, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "No proposals are awaiting review") {
		t.Errorf("a decided proposal still shows as pending: %q", out.String())
	}
}

func TestPendingProposalsSummaryCountsByKind(t *testing.T) {
	path, p := journalWithProposal(t)

	s, err := PendingProposalsSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Ownership != 1 || s.Total != 1 {
		t.Errorf("summary = %+v, want one pending ownership proposal", s)
	}

	line := s.Line()
	for _, want := range []string{"1 proposal(s) awaiting review", "1 ownership relationship",
		"amass review proposals"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary line %q omits %q", line, want)
		}
	}

	// A decided proposal leaves nothing pending, so the summary is empty and
	// its line says nothing for a caller to print.
	if err := rejectProposal(path, p.ID, "jeff", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	s, err = PendingProposalsSummary(path)
	if err != nil {
		t.Fatal(err)
	}
	if s.Total != 0 {
		t.Errorf("summary = %+v, want nothing pending after a decision", s)
	}
	if s.Line() != "" {
		t.Errorf("empty summary still produced a line: %q", s.Line())
	}
}

func TestSignalsExplainEachRule(t *testing.T) {
	var out bytes.Buffer
	if err := listSignals("json", false, &out); err != nil {
		t.Fatal(err)
	}
	for _, s := range lens.OwnershipSignals() {
		if !strings.Contains(out.String(), s.Title+" ("+s.ID+")") || !strings.Contains(out.String(), s.Rationale) {
			t.Errorf("text listing lacks %s or its rationale", s.ID)
		}
	}

	out.Reset()
	if err := listSignals("markdown", true, &out); err != nil || out.String() != lens.SignalsMarkdown() {
		t.Errorf("markdown listing differs from SIGNALS.md source: %v", err)
	}
	if err := listSignals("mermaid", true, &out); err == nil {
		t.Error("an unsupported format was accepted")
	}
}

// A run reports the proposals it raised, not the journal's backlog: one
// recorded before the run started is not counted, and a record without a time
// counts only when everything is asked for.
func TestPendingProposalsSinceScopesToARun(t *testing.T) {
	path, _ := journalWithProposal(t) // recorded without a time (a legacy record)

	before := time.Now().UTC().Add(-time.Hour)
	runStart := time.Now().UTC()
	mk := func(from string, at time.Time) review.OwnershipProposal {
		edge := lens.ProposedEdge{FromID: from, FromType: "ContactRecord", From: "https://rdap.example/" + from,
			Label: "organization", RelationType: "SimpleRelation", ToID: "2", ToType: "Organization",
			To: "Synthetic University"}
		return review.OwnershipProposal{ID: review.ProposalID(edge), Owner: "Synthetic University", OwnerID: "2",
			Asset: edge.From, AssetID: from, AssetType: "ContactRecord", Edge: edge, Score: 0.9,
			Decision: lens.GapPropose, CreatedAt: at}
	}
	if _, err := (&review.Journal{Path: path}).SubmitOwnership([]review.OwnershipProposal{
		mk("10", before), mk("11", runStart.Add(time.Minute))}); err != nil {
		t.Fatal(err)
	}

	all, err := PendingProposalsSince(path, time.Time{})
	if err != nil || all.Ownership != 3 {
		t.Errorf("all pending = %+v, %v; want 3", all, err)
	}
	run, err := PendingProposalsSince(path, runStart)
	if err != nil || run.Ownership != 1 || run.Total != 1 {
		t.Errorf("pending during the run = %+v, %v; want 1", run, err)
	}
}

// A proposal whose asset is no longer stored (the database was reset since)
// is hidden from the live listings with a count; without a check it is shown.
func TestLiveListingsHideProposalsForMissingAssets(t *testing.T) {
	path, p := journalWithProposal(t) // its contact record is entity "1"
	gone := func(id string) bool { return id != "1" }

	text, err := PendingProposalsTextLive(path, gone)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(text, p.ID) || !strings.Contains(text, "1 older proposal(s) are hidden") ||
		!strings.Contains(text, "No proposals are awaiting review") {
		t.Errorf("live pending listing:\n%s", text)
	}

	all, err := PendingProposalsText(path)
	if err != nil || !strings.Contains(all, p.ID) || strings.Contains(all, "hidden") {
		t.Errorf("unchecked pending listing:\n%s (%v)", all, err)
	}

	// Once the AI applies it, the applied listing hides it too.
	if err := approveProposal(context.Background(), &fakeOwnershipWriter{}, path, p.ID, review.AutomaticReviewer,
		&bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	applied, err := AppliedProposalsTextLive(path, gone)
	if err != nil || strings.Contains(applied, p.ID) {
		t.Errorf("live applied listing:\n%s (%v)", applied, err)
	}
	if applied, err := AppliedProposalsTextLive(path, nil); err != nil || !strings.Contains(applied, p.ID) {
		t.Errorf("unchecked applied listing:\n%s (%v)", applied, err)
	}
}
