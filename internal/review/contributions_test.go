// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

type fakeContributionWriter struct {
	source  string
	written []ContributedItem
	undone  []ContributionWrite
	fail    error
}

func (f *fakeContributionWriter) WriteContribution(_ context.Context, source string,
	items []ContributedItem) (ContributionWrite, error) {
	f.source, f.written = source, items
	return ContributionWrite{EntityIDs: []string{"1"}}, f.fail
}

func (f *fakeContributionWriter) UndoContribution(_ context.Context, _ string, w ContributionWrite) error {
	f.undone = append(f.undone, w)
	return nil
}

func contributedFQDN(name string) ContributedItem {
	return ContributedItem{Kind: ContributedAsset, AssetType: "FQDN", Fields: map[string]any{"name": name},
		Evidence: "the user said so"}
}

func TestCheckContribution(t *testing.T) {
	one, two := 1, 0
	too := make([]ContributedItem, MaxContributedItems+1)
	for i := range too {
		too[i] = contributedFQDN("a.example.com")
	}

	for name, items := range map[string][]ContributedItem{
		"none":        nil,
		"too many":    too,
		"no evidence": {{Kind: ContributedAsset, AssetType: "FQDN", Fields: map[string]any{"name": "x"}}},
		"later item": {{Kind: ContributedRelation, Label: "node", From: &AssetRef{Item: &one},
			To: &AssetRef{Item: &one}, Evidence: "x"}, contributedFQDN("a.example.com")},
		"relation item": {contributedFQDN("a.example.com"), {Kind: ContributedRelation, Label: "node",
			From: &AssetRef{Item: &two}, To: &AssetRef{Item: &one}, Evidence: "x"}},
		"partial ref": {{Kind: ContributedProperty, Target: &AssetRef{Type: "FQDN"},
			Fields: map[string]any{"property_name": "n"}, Evidence: "x"}},
		"bad kind": {{Kind: "rumor", Evidence: "x"}},
		"bad confidence": {{Kind: ContributedAsset, AssetType: "FQDN", Fields: map[string]any{"name": "x"},
			Evidence: "x", Confidence: 101}},
	} {
		if err := CheckContribution(items); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	ok := []ContributedItem{contributedFQDN("a.example.com"), {Kind: ContributedRelation, Label: "node",
		From: &AssetRef{Type: "FQDN", Field: "name", Value: "example.com"}, To: &AssetRef{Item: &two},
		Evidence: "x"}}
	if err := CheckContribution(ok); err != nil {
		t.Fatal(err)
	}
}

func TestApplyAndRetractContribution(t *testing.T) {
	ctx := context.Background()
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	w := &fakeContributionWriter{}

	c, err := ApplyContribution(ctx, w, j, "Claude Desktop", "jeff", []ContributedItem{contributedFQDN("a.example.com")})
	if err != nil {
		t.Fatal(err)
	}
	if !IsContribution(c.ID) || w.source != "amass-ai:claude-desktop" || c.Source != w.source {
		t.Fatalf("contribution %s from %q (writer saw %q)", c.ID, c.Source, w.source)
	}
	if err := j.RecordContributionRuns(c, []string{"run-1"}); err != nil {
		t.Fatal(err)
	}

	all, err := j.Contributions()
	if err != nil || len(all) != 1 || all[0].Status != ProposalApplied || len(all[0].Runs) != 1 {
		t.Fatalf("contributions = %+v, %v", all, err)
	}
	if text := FormatContributions(all); !strings.Contains(text, "a.example.com") ||
		!strings.Contains(text, "run-1") {
		t.Fatalf("format = %q", text)
	}

	if err := RetractContribution(ctx, w, j, c.ID, "jeff"); err != nil {
		t.Fatal(err)
	}
	if len(w.undone) != 1 || len(w.undone[0].EntityIDs) != 1 {
		t.Fatalf("undone = %+v", w.undone)
	}
	all, _ = j.Contributions()
	if len(all) != 1 || all[0].Status != ProposalRetracted {
		t.Fatalf("after retraction = %+v", all)
	}
	if err := RetractContribution(ctx, w, j, c.ID, "jeff"); err == nil {
		t.Fatal("retracted twice")
	}
}

// A write that fails part way is undone, and nothing is journaled.
func TestApplyContributionUndoesAFailedWrite(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "journal.jsonl")}
	w := &fakeContributionWriter{fail: errors.New("item 1: no")}

	if _, err := ApplyContribution(context.Background(), w, j, "c", "jeff",
		[]ContributedItem{contributedFQDN("a.example.com")}); err == nil {
		t.Fatal("applied")
	}
	if len(w.undone) != 1 {
		t.Fatalf("undone = %+v", w.undone)
	}
	if all, err := j.Contributions(); err != nil || len(all) != 0 {
		t.Fatalf("journaled = %+v, %v", all, err)
	}
}
