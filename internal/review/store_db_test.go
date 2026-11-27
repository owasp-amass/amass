// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/coord"
)

// A journal kept in the database records under the review topic, keyed by
// what each record is about, and reads only what was appended since its last
// read; its readers see the same records a file journal gives them.
func TestJournalKeptInTheDatabase(t *testing.T) {
	db := &coord.FakeStore{}
	j := OpenJournal(filepath.Join(t.TempDir(), "review.jsonl"), db)
	if !j.Shared() || j.Name() == j.Path {
		t.Fatalf("journal %+v is not shared", j)
	}
	if OpenJournal("", db) != nil {
		t.Error("a journal with no path was opened")
	}
	if OpenJournal("review.jsonl", nil).Shared() {
		t.Error("a journal without a database is shared")
	}

	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "o", Asset: "a.example", Status: ProposalPending}); err != nil {
		t.Fatal(err)
	}
	all, err := j.ScopeExpansions()
	if err != nil || len(all) != 1 || all[0].Asset != "a.example" {
		t.Fatalf("expansions = %+v, %v", all, err)
	}
	if r := db.Records()[0]; r.Topic != JournalTopic || r.Kind != "scope_expansion" || r.Key != all[0].ID ||
		r.Actor == "" {
		t.Errorf("record = %+v", r)
	}

	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "o", Asset: "b.example", Status: ProposalPending}); err != nil {
		t.Fatal(err)
	}
	if all, err = j.ScopeExpansions(); err != nil || len(all) != 2 {
		t.Fatalf("after another = %+v, %v", all, err)
	}
	if got := db.Reads; len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Errorf("reads started at %v, want 0 then 1", got)
	}
	if _, err := os.Stat(j.Path); !os.IsNotExist(err) {
		t.Error("a journal kept in the database wrote its file")
	}
}

// A file journal is imported into the database once, in order; until it is,
// the shared journal says so.
func TestImportJournal(t *testing.T) {
	dir := t.TempDir()
	file := &Journal{Path: filepath.Join(dir, "review.jsonl")}
	for _, asset := range []string{"a.example", "b.example"} {
		if err := file.RecordScopeExpansion(ScopeExpansion{OrgID: "o", Asset: asset, Status: ProposalPending}); err != nil {
			t.Fatal(err)
		}
	}

	db := &coord.FakeStore{}
	j := OpenJournal(file.Path, db)
	if !j.FileNotImported() {
		t.Error("an unimported file journal is not reported")
	}
	if _, _, err := file.ImportJournal(file.Path); err == nil {
		t.Error("a file journal imported into itself")
	}

	n, done, err := j.ImportJournal(file.Path)
	if err != nil || done || n != 2 {
		t.Fatalf("import = %d, %v, %v", n, done, err)
	}
	all, err := j.ScopeExpansions()
	if err != nil || len(all) != 2 || all[0].Asset != "a.example" || all[1].Asset != "b.example" {
		t.Fatalf("imported = %+v, %v", all, err)
	}
	if j.FileNotImported() {
		t.Error("an imported file journal is reported")
	}

	if n, done, err = j.ImportJournal(file.Path); err != nil || !done || n != 2 {
		t.Fatalf("second import = %d, %v, %v", n, done, err)
	}
	if all, _ = j.ScopeExpansions(); len(all) != 2 || len(db.Records()) != 3 {
		t.Errorf("a second import appended records: %d", len(db.Records()))
	}
}

// A file journal's last line still being written is read next time; a
// read-only journal of records reads them and takes no writes.
func TestJournalPartialLineAndReadOnly(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if err := j.RecordScopeExpansion(ScopeExpansion{OrgID: "o", Asset: "a.example", Status: ProposalPending}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(j.Path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.WriteString(`{"kind":"scope_expansion","data":`)
	_ = f.Close()

	lines, err := j.History()
	if err != nil || len(lines) != 1 {
		t.Fatalf("history = %d lines, %v", len(lines), err)
	}

	ro := JournalOf(lines)
	if all, err := ro.ScopeExpansions(); err != nil || len(all) != 1 {
		t.Fatalf("read-only expansions = %+v, %v", all, err)
	}
	if err := ro.RecordScopeExpansion(ScopeExpansion{OrgID: "o", Asset: "b.example", Status: ProposalPending}); err == nil {
		t.Error("a read-only journal took a write")
	}
	var head struct{ Kind string }
	if json.Unmarshal(lines[0], &head) != nil || head.Kind != "scope_expansion" {
		t.Errorf("line = %s", lines[0])
	}
}
