// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// statementStore keeps the properties written to one File.
type statementStore struct {
	file      *dbt.Entity
	props     map[string]*oamgen.SimpleProperty
	next      int
	failAfter int
}

func newStatementStore() *statementStore {
	return &statementStore{
		file:  &dbt.Entity{ID: "f1", Asset: &oamfile.File{URL: "https://www.sunyit.edu/plan.pdf"}},
		props: map[string]*oamgen.SimpleProperty{},
	}
}

func (s *statementStore) FindEntityById(_ context.Context, id string) (*dbt.Entity, error) {
	if id != s.file.ID {
		return nil, errors.New("not found")
	}
	return s.file, nil
}

func (s *statementStore) CreateEntityProperty(_ context.Context, _ *dbt.Entity, p oam.Property) (*dbt.EntityTag, error) {
	if s.failAfter > 0 && s.next >= s.failAfter {
		return nil, errors.New("database unavailable")
	}
	s.next++
	id := fmt.Sprintf("t%d", s.next)
	s.props[id] = p.(*oamgen.SimpleProperty)
	return &dbt.EntityTag{ID: id, Property: p}, nil
}

func (s *statementStore) DeleteEntityTag(_ context.Context, id string) error {
	if _, ok := s.props[id]; !ok {
		return errors.New("tag not found")
	}
	delete(s.props, id)
	return nil
}

var testStatements = []StoredStatement{
	{Subject: "https://www.sunyit.edu/plan.pdf", SubjectType: "File", Predicate: PredicateIsA,
		Object: "annual_report"},
	{Subject: "SUNY Polytechnic Institute", SubjectType: "Organization", Predicate: "unit_of",
		Object: "State University of New York", ObjectType: "Organization",
		Quote: "SUNY Polytechnic Institute is a campus of the State University of New York."},
}

// Statements are stored on the File as amass-ai doc_statement properties, the
// journal keeps only counts and tags, and undo removes exactly those
// properties.
func TestStoreAndUndoDocumentStatements(t *testing.T) {
	ctx := context.Background()
	s := newStatementStore()
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}

	rec, err := StoreDocumentStatements(ctx, s, j, "f1", "https://www.sunyit.edu/plan.pdf", "abc123",
		"ollama/qwen3", testStatements)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.TagIDs) != 2 || len(s.props) != 2 || rec.Predicates["unit_of"] != 1 || rec.Predicates[PredicateIsA] != 1 {
		t.Fatalf("record %+v, props %d", rec, len(s.props))
	}
	for _, p := range s.props {
		var v StoredStatement
		if p.PropertyName != PropDocStatement || json.Unmarshal([]byte(p.PropertyValue), &v) != nil ||
			v.Source != InferenceSource || v.Model != "ollama/qwen3" || v.SHA256 != "abc123" {
			t.Fatalf("stored property %+v", p)
		}
	}

	hist, err := j.History()
	if err != nil || len(hist) != 1 {
		t.Fatalf("history %d, %v", len(hist), err)
	}
	if b := string(hist[0]); strings.Contains(b, "campus of") || strings.Contains(b, "SUNY Polytechnic Institute") {
		t.Fatalf("journal holds document text: %s", b)
	}

	ids, err := j.StoredDocumentReadings("f1")
	if err != nil || len(ids) != 1 || ids[0] != rec.ID {
		t.Fatalf("stored readings %v, %v", ids, err)
	}

	// a tag someone already removed does not stop the undo
	delete(s.props, rec.TagIDs[0])
	if err := UndoDocumentStatements(ctx, s, j, rec.ID, "jeff"); err != nil {
		t.Fatal(err)
	}
	if len(s.props) != 0 {
		t.Fatalf("undo left %d properties", len(s.props))
	}
	if ids, _ := j.StoredDocumentReadings("f1"); len(ids) != 0 {
		t.Fatalf("undone reading still stored: %v", ids)
	}
	if err := UndoDocumentStatements(ctx, s, j, rec.ID, "jeff"); err == nil {
		t.Fatal("a reading was undone twice")
	}
	recs, _ := j.DocumentStatementRecords()
	if len(recs) != 1 || recs[0].Status != StatementsUndone || recs[0].Actor != "jeff" {
		t.Fatalf("records %+v", recs)
	}
}

// A failed write removes what it had written, so nothing is left that the
// journal cannot undo.
func TestStoreDocumentStatementsRollsBack(t *testing.T) {
	ctx := context.Background()
	s := newStatementStore()
	s.failAfter = 1
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}

	if _, err := StoreDocumentStatements(ctx, s, j, "f1", "u", "h", "m", testStatements); err == nil {
		t.Fatal("expected the write to fail")
	}
	if len(s.props) != 0 {
		t.Fatalf("rollback left %d properties", len(s.props))
	}
	if recs, _ := j.DocumentStatementRecords(); len(recs) != 0 {
		t.Fatalf("a failed reading was journaled: %+v", recs)
	}

	// statements need a stored File
	if _, err := StoreDocumentStatements(ctx, newStatementStore(), j, "missing", "u", "h", "m", testStatements); err == nil {
		t.Fatal("stored on a missing entity")
	}
}

// A reading that found nothing is journaled, so the version it read is not
// read again; undoing a reading frees its version.
func TestEmptyReadingMarksTheVersionRead(t *testing.T) {
	ctx := context.Background()
	s := newStatementStore()
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}

	rec, err := StoreDocumentStatements(ctx, s, j, "f1", "u", "v1", "m", nil)
	if err != nil || rec.ID == "" || len(s.props) != 0 {
		t.Fatalf("empty reading %+v, %v", rec, err)
	}
	read, err := j.ReadVersions()
	if err != nil || !read["v1"] {
		t.Fatalf("read versions %v, %v", read, err)
	}
	if ids, _ := j.StoredVersionReadings("v1"); len(ids) != 1 {
		t.Fatalf("version readings %v", ids)
	}
	if err := UndoDocumentStatements(ctx, s, j, rec.ID, "jeff"); err != nil {
		t.Fatal(err)
	}
	if read, _ := j.ReadVersions(); read["v1"] {
		t.Fatal("an undone reading still marks its version read")
	}
}

// A version read only in part is not counted as read; the next reading starts
// at the furthest offset reached, and once a reading reaches the end the
// version is read and has no progress left.
func TestPartialReadingsContinue(t *testing.T) {
	ctx := context.Background()
	s := newStatementStore()
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}

	for _, through := range []int{24000, 48000} {
		if _, err := StorePartialDocumentStatements(ctx, s, j, "f1", "u", "v1", "m", nil, through); err != nil {
			t.Fatal(err)
		}
	}
	if read, _ := j.ReadVersions(); read["v1"] {
		t.Error("a version read only in part is counted as read")
	}
	progress, err := j.VersionProgress()
	if err != nil || progress["v1"] != 48000 {
		t.Fatalf("progress %v, %v; want the furthest offset, 48000", progress, err)
	}

	if _, err := StorePartialDocumentStatements(ctx, s, j, "f1", "u", "v1", "m", nil, 0); err != nil {
		t.Fatal(err)
	}
	if read, _ := j.ReadVersions(); !read["v1"] {
		t.Error("a version read to its end is not counted as read")
	}
	if progress, _ := j.VersionProgress(); len(progress) != 0 {
		t.Errorf("a version read to its end still has progress %v", progress)
	}
}
