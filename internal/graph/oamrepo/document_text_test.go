// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	oamfile "github.com/owasp-amass/open-asset-model/file"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// A graph served to models not allowed to read documents shows a marker in
// place of each passage, one per passage so they can still be counted, and
// will not search passages by value; other properties are untouched.
func TestWithholdDocumentText(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "doctext.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx := context.Background()
	fent, err := repo.CreateAsset(ctx, &oamfile.File{URL: "https://www.example.com/plan.pdf", Type: "application/pdf"})
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []*oamgen.SimpleProperty{
		{PropertyName: "doc_statement", PropertyValue: "The Foundation is a division of the College."},
		{PropertyName: "doc_statement", PropertyValue: "Jane Doe, Chief Information Officer."},
		{PropertyName: "doc_title", PropertyValue: "IT Plan"},
	} {
		if _, err := repo.CreateEntityProperty(ctx, fent, p); err != nil {
			t.Fatal(err)
		}
	}

	values := func(a Adapter) (passages []string, title string) {
		t.Helper()
		ev, err := a.Evidence(ctx, fent.ID, 100)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ev {
			if sp, ok := e.Property.(*oamgen.SimpleProperty); ok {
				switch sp.PropertyName {
				case "doc_statement":
					passages = append(passages, sp.PropertyValue)
				case "doc_title":
					title = sp.PropertyValue
				}
			}
		}
		return passages, title
	}

	open, _ := values(Adapter{Repo: repo})
	if len(open) != 2 || !strings.Contains(strings.Join(open, " "), "division of the College") {
		t.Errorf("shared passages %q", open)
	}

	withheld, title := values(Adapter{Repo: repo, WithholdDocumentText: true})
	if len(withheld) != 2 || withheld[0] == withheld[1] || title != "IT Plan" {
		t.Errorf("withheld passages %q, title %q", withheld, title)
	}
	for _, v := range withheld {
		if strings.Contains(v, "College") || strings.Contains(v, "Jane") || !strings.HasPrefix(v, "[document text withheld") {
			t.Errorf("passage text leaked: %q", v)
		}
	}
	if !graph.IsDocumentTextProperty("DOC_STATEMENT") || graph.IsDocumentTextProperty("doc_title") {
		t.Error("document text property names")
	}

	found, _, err := Adapter{Repo: repo, WithholdDocumentText: true}.FindByTagValue(ctx, "File", "doc_statement", "College", true, 10)
	if err != nil || len(found) != 0 {
		t.Errorf("withheld passages were searchable: %v, %v", found, err)
	}
}
