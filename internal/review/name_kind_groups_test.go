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

func groupProposal(record, label, name string) NameKindProposal {
	return NameKindProposal{ID: NameKindProposalID(record, label, name), RecordID: record, RecordType: "File",
		Label: label, Name: name, Reasons: []string{"it does not read as a person's name"}}
}

// The proposals of one name in one field are answered, listed and decided
// together; another field's are not.
func TestNameKindGroups(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	a, b, c := groupProposal("f1", "author", "jgordon"), groupProposal("f2", "author", "JGordon"),
		groupProposal("f3", "author", " jgordon ")
	other := groupProposal("c1", "person", "jgordon")
	if _, err := j.SubmitNameKinds([]NameKindProposal{a, b, c, other}); err != nil {
		t.Fatal(err)
	}
	if a.Group() != b.Group() || a.Group() != c.Group() || a.Group() == other.Group() {
		t.Fatal("groups: case and spacing should not matter, the field should")
	}

	if _, ok, _ := j.NameKindGroupAnswer(a); ok {
		t.Error("an answer before any was given")
	}
	if g, _ := j.UnansweredNameKindGroup(a); len(g) != 3 || g[0].ID != a.ID {
		t.Errorf("unanswered group = %+v", g)
	}
	if err := j.RecordNameKindAdvice(NameKindAdvice{ProposalID: b.ID, Model: "model m", Kind: NameKindPerson,
		Confidence: 70, Reason: "a login"}); err != nil {
		t.Fatal(err)
	}
	ans, ok, err := j.NameKindGroupAnswer(a)
	if err != nil || !ok || ans.ProposalID != a.ID || ans.Kind != NameKindPerson || ans.Confidence != 70 ||
		!strings.Contains(ans.Reason, b.ID) {
		t.Errorf("group answer = %+v, %v, %v", ans, ok, err)
	}
	if _, ok, _ := j.NameKindGroupAnswer(other); ok {
		t.Error("another field's proposal took the answer")
	}
	if g, _ := j.UnansweredNameKindGroup(a); len(g) != 2 {
		t.Errorf("the advised proposal is still unanswered: %+v", g)
	}

	entries, _ := j.NameKindEntries()
	text := FormatNameKindEntries(entries)
	if strings.Count(text, "is \"") != 2 || !strings.Contains(text, "and 2 more, decided with it") ||
		strings.Count(text, "advice from model m") != 1 {
		t.Errorf("listing:\n%s", text)
	}

	w := &fakeNameKindApplier{}
	if o, err := ApplyNameKindGroup(ctx, w, j, b.ID, NameKindPerson, "jeff", 100, "", true); err != nil ||
		len(o) != 1 || o[0].ProposalID != b.ID {
		t.Fatalf("-only = %+v, %v", o, err)
	}
	o, err := ApplyNameKindGroup(ctx, w, j, a.ID, NameKindPerson, "jeff", 100, "", false)
	if err != nil || len(o) != 2 || o[0].ProposalID != a.ID || o[1].ProposalID != c.ID {
		t.Fatalf("group = %+v, %v", o, err)
	}
	ans, ok, _ = j.NameKindGroupAnswer(groupProposal("f4", "author", "jgordon"))
	if !ok || ans.Model != "jeff" || ans.Confidence != 100 || !strings.Contains(ans.Reason, "decided for") {
		t.Errorf("a later record's answer = %+v", ans)
	}

	if ids, err := RejectNameKindGroup(j, other.ID, "jeff", false); err != nil || len(ids) != 1 {
		t.Errorf("reject = %v, %v", ids, err)
	}
	if err := RetractNameKind(ctx, w, j, c.ID, "jeff"); err != nil {
		t.Fatal(err)
	}
	state, _ := j.NameKindState()
	if state[a.ID].Status != ProposalApplied || state[c.ID].Status != ProposalRetracted {
		t.Error("retracting one decision of a group touched another")
	}
}

// An answer copied from proposal to proposal of a group keeps the one note
// naming the proposal it was first given for.
func TestGroupReasonKeepsFirstNote(t *testing.T) {
	first := groupReason("answered for", "nk-1", "a login of first initial plus surname")
	if first != "answered for nk-1, the same name in the same field: a login of first initial plus surname" {
		t.Fatalf("first = %q", first)
	}
	if again := groupReason("answered for", "nk-2", first); again != first {
		t.Errorf("copied again = %q, want %q", again, first)
	}
	if got := groupReason("decided for", "nk-3", ""); got != "decided for nk-3, the same name in the same field" {
		t.Errorf("no reason = %q", got)
	}
}
