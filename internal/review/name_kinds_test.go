// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

// fakeNameKindApplier records what a decision would write.
type fakeNameKindApplier struct {
	applied   []string
	retracted []string
}

func (f *fakeNameKindApplier) ApplyNameKind(_ context.Context, p NameKindProposal, kind string,
	_ int) (NameKindOutcome, error) {
	f.applied = append(f.applied, p.Name+"="+kind)
	return NameKindOutcome{EntityID: kind + ":1", EdgeID: "e1", Created: true}, nil
}

func (f *fakeNameKindApplier) RetractNameKind(_ context.Context, p NameKindProposal, o NameKindOutcome) error {
	f.retracted = append(f.retracted, p.Name+"="+o.EntityID)
	return nil
}

func nameKindProposal(name string) NameKindProposal {
	return NameKindProposal{ID: NameKindProposalID("rec1", "person", name), RecordID: "rec1",
		RecordType: "ContactRecord", Label: "person", Name: name, Reasons: []string{"one word"}}
}

func TestNameKindSubmitDedupes(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	p := nameKindProposal("Registrar")

	added, err := j.SubmitNameKinds([]NameKindProposal{p, p})
	if err != nil || len(added) != 1 {
		t.Fatalf("first submit added %d, err %v; want 1", len(added), err)
	}
	if added, err = j.SubmitNameKinds([]NameKindProposal{p}); err != nil || len(added) != 0 {
		t.Fatalf("second submit added %d, err %v; want 0", len(added), err)
	}
	if !IsNameKindProposal(p.ID) {
		t.Errorf("%s is not recognized as a name proposal", p.ID)
	}
	if p.ID != NameKindProposalID("rec1", "person", " registrar ") {
		t.Error("the ID changes with the name's case or spacing")
	}
	if _, err := j.SubmitNameKinds([]NameKindProposal{{ID: "nk-x", RecordID: "rec1"}}); err == nil {
		t.Error("a proposal without a label and name was accepted")
	}
}

// A name kept with no answer is asked again when it is met again; one with
// advice or a decision is not.
func TestNameKindsToAsk(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	failed, advised, decided := nameKindProposal("aaronrobertson"), nameKindProposal("Registrar"),
		nameKindProposal("Pat Lee")

	ask, err := j.NameKindsToAsk([]NameKindProposal{failed, advised, decided})
	if err != nil || len(ask) != 3 {
		t.Fatalf("first ask = %v, %v; want all three", ask, err)
	}
	if err := j.RecordNameKindAdvice(NameKindAdvice{ProposalID: advised.ID, Model: "m",
		Kind: NameKindOrganization, Confidence: 70}); err != nil {
		t.Fatal(err)
	}
	if _, err := ApplyNameKind(context.Background(), &fakeNameKindApplier{}, j, decided.ID, NameKindPerson,
		"jeff", 100, ""); err != nil {
		t.Fatal(err)
	}

	ask, err = j.NameKindsToAsk([]NameKindProposal{failed, advised, decided})
	if err != nil || len(ask) != 1 || ask[0].ID != failed.ID {
		t.Fatalf("second ask = %v, %v; want only the unanswered name", ask, err)
	}
	if added, _ := j.SubmitNameKinds([]NameKindProposal{failed}); len(added) != 0 {
		t.Error("submitting returned a proposal already recorded")
	}
	if entries, _ := j.NameKindEntries(); len(entries) != 3 {
		t.Errorf("asking again recorded the proposals again: %d entries", len(entries))
	}
}

func TestNameKindApplyRetract(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	p := nameKindProposal("Pat Lee")
	if _, err := j.SubmitNameKinds([]NameKindProposal{p}); err != nil {
		t.Fatal(err)
	}

	w := &fakeNameKindApplier{}
	if _, err := ApplyNameKind(ctx, w, j, p.ID, "role", "jeff", 100, ""); err == nil {
		t.Fatal("a kind other than person or organization was accepted")
	}
	if _, err := ApplyNameKind(ctx, w, j, p.ID, NameKindPerson, "", 100, ""); err == nil {
		t.Fatal("a decision without a reviewer was accepted")
	}

	o, err := ApplyNameKind(ctx, w, j, p.ID, NameKindPerson, "jeff", 100, "")
	if err != nil {
		t.Fatal(err)
	}
	if o.EntityID != "person:1" || len(w.applied) != 1 || w.applied[0] != "Pat Lee=person" {
		t.Fatalf("applied %v, outcome %+v", w.applied, o)
	}
	if _, err := ApplyNameKind(ctx, w, j, p.ID, NameKindPerson, "jeff", 100, ""); err == nil {
		t.Fatal("an applied proposal was applied again")
	}
	if err := RejectNameKind(j, p.ID, "jeff"); err == nil {
		t.Fatal("an applied proposal was rejected")
	}

	state, err := j.NameKindState()
	if err != nil {
		t.Fatal(err)
	}
	if e := state[p.ID]; e.Status != ProposalApplied || e.Outcome.Kind != NameKindPerson {
		t.Fatalf("state %+v", e)
	}

	if err := RetractNameKind(ctx, w, j, p.ID, "jeff"); err != nil {
		t.Fatal(err)
	}
	if len(w.retracted) != 1 || w.retracted[0] != "Pat Lee=person:1" {
		t.Fatalf("retracted %v", w.retracted)
	}
	if err := RetractNameKind(ctx, w, j, p.ID, "jeff"); err == nil {
		t.Fatal("a retracted proposal was retracted again")
	}
}

func TestNameKindReject(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	p := nameKindProposal("Domain Administrator")
	if _, err := j.SubmitNameKinds([]NameKindProposal{p}); err != nil {
		t.Fatal(err)
	}
	if err := RejectNameKind(j, p.ID, "jeff"); err != nil {
		t.Fatal(err)
	}

	entries, err := j.NameKindEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Status != ProposalRejected {
		t.Fatalf("entries %+v", entries)
	}
	if text := FormatNameKindEntries(entries); !strings.Contains(text, "Domain Administrator") ||
		!strings.Contains(text, "one word") {
		t.Errorf("listing is missing the name or its evidence:\n%s", text)
	}
}

func TestNameKindAdvice(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	p := nameKindProposal("Sarah Church")
	if _, err := j.SubmitNameKinds([]NameKindProposal{p}); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordNameKindAdvice(NameKindAdvice{ProposalID: p.ID, Model: "model test"}); err == nil {
		t.Fatal("advice without a kind was recorded")
	}
	if err := j.RecordNameKindAdvice(NameKindAdvice{ProposalID: p.ID, Model: "model test",
		Kind: NameKindPerson, Confidence: 70, Reason: "an email names her", Cites: []string{"one word"}}); err != nil {
		t.Fatal(err)
	}

	entries, err := j.NameKindEntries()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Status != ProposalPending || entries[0].Advice == nil ||
		entries[0].Advice.Kind != NameKindPerson {
		t.Fatalf("entries %+v", entries)
	}
	if text := FormatNameKindEntries(entries); !strings.Contains(text, "advice from model test: person at confidence 70") {
		t.Errorf("listing is missing the advice:\n%s", text)
	}
}
