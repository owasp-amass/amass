// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestOwnershipProposalsKeepOnlyAttachableCandidates(t *testing.T) {
	ps := OwnershipProposals(gapReport(t))
	if len(ps) != 1 {
		t.Fatalf("proposals = %+v, want the shared-registrant contact only", ps)
	}

	p := ps[0]
	if p.Asset != "https://rdap.example/alumni" || p.Decision != GapPropose || p.Owner != "Colgate University" {
		t.Errorf("proposal = %+v", p)
	}
	if p.ID != ProposalID(p.Edge) || !strings.HasPrefix(p.ID, "own-") {
		t.Errorf("ID = %q", p.ID)
	}
	if len(p.Signals) != 2 || len(p.Evidence) == 0 {
		t.Errorf("signals = %v, evidence = %v", p.Signals, p.Evidence)
	}
	for _, ev := range p.Evidence {
		if !strings.Contains(ev, "-->") || strings.HasPrefix(ev, ":") {
			t.Errorf("evidence line %q", ev)
		}
	}
}

func TestOwnershipJournalLifecycle(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	entries, err := j.OwnershipEntries()
	if err != nil || len(entries) != 0 {
		t.Fatalf("empty journal = %v, %v", entries, err)
	}

	ps := OwnershipProposals(gapReport(t))
	added, err := j.SubmitOwnership(ps)
	if err != nil || len(added) != 1 {
		t.Fatalf("submit = %v, %v", added, err)
	}
	if again, err := j.SubmitOwnership(ps); err != nil || len(again) != 0 {
		t.Fatalf("resubmit added %v, %v; want nothing", again, err)
	}

	id := added[0].ID
	if err := j.RecordOwnership(OwnershipOutcome{ProposalID: id, Status: ProposalApplied, Reviewer: "jeff"}); err == nil {
		t.Error("applied without an edge ID was accepted")
	}
	if err := j.RecordOwnership(OwnershipOutcome{ProposalID: id, Status: "accepted", Reviewer: "jeff"}); err == nil {
		t.Error("unknown status was accepted")
	}
	if err := j.RecordOwnership(OwnershipOutcome{ProposalID: id, Status: ProposalApplied, Reviewer: "jeff",
		EdgeID: "42"}); err != nil {
		t.Fatal(err)
	}

	entries, err = j.OwnershipEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %v, %v", entries, err)
	}
	if e := entries[0]; e.Status != ProposalApplied || e.Outcome == nil || e.Outcome.EdgeID != "42" {
		t.Errorf("entry = %+v", e)
	}

	text := FormatOwnershipEntries(entries)
	for _, want := range []string{id, "applied by jeff", "(edge 42)", "would record: ContactRecord"} {
		if !strings.Contains(text, want) {
			t.Errorf("listing lacks %q:\n%s", want, text)
		}
	}
}
