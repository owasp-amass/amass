// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/classify"
	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

func horizontalModel(id string) *classify.LinearModel {
	return &classify.LinearModel{ModelID: id, Task: HorizontalTask, FeatureVersion: HorizontalFeatureVersion,
		SkipThreshold: 0.7, ReviewThreshold: 0.7, Classes: []classify.LinearClass{
			{Label: labelNegative, Weights: map[string]float64{"x": 0}},
			{Label: labelPositive, Weights: map[string]float64{"x": 1}}}}
}

// With the journal in the Asset Database, a trained model is kept there and
// the newest is loaded, by any engine on the database; a model file beside
// the journal is used until the database has one.
func TestModelsAreKeptWithTheJournal(t *testing.T) {
	dir := t.TempDir()
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(dir, "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	path := filepath.Join(dir, "review.jsonl")
	j := review.OpenJournal(path, repo)
	if !j.Shared() {
		t.Fatal("SQLite keeps no journal")
	}

	// a model file from before is used while the database has none
	if err := HorizontalKind.Save(horizontalModel("from-file"), HorizontalKind.Path(path)); err != nil {
		t.Fatal(err)
	}
	if m, where, err := HorizontalKind.Find(j); err != nil || m == nil || m.ModelID != "from-file" ||
		where != HorizontalKind.Path(path) {
		t.Fatalf("Find = %v, %q, %v", m, where, err)
	}

	for _, id := range []string{"first", "second"} {
		if err := HorizontalKind.Keep(j, horizontalModel(id)); err != nil {
			t.Fatal(err)
		}
	}
	// another engine opens its own journal on the same database
	other := review.OpenJournal(filepath.Join(t.TempDir(), "elsewhere.jsonl"), repo)
	m, where, err := HorizontalKind.Find(other)
	if err != nil || m == nil || m.ModelID != "second" || !strings.Contains(where, "Asset Database") {
		t.Fatalf("Find = %v, %q, %v; want the newest model, from the database", m, where, err)
	}
	if s, err := LoadHorizontalScorer(other); err != nil || s == nil || s.ModelName() != "second" {
		t.Errorf("LoadHorizontalScorer = %v, %v", s, err)
	}
	if m, _ := NameKindKind.LoadFor(other); m != nil {
		t.Errorf("another kind loaded %s", m.ModelID)
	}

	// without the database, Keep writes the file beside the journal
	file := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if err := HorizontalKind.Keep(file, horizontalModel("file-only")); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(HorizontalKind.Path(file.Path)); err != nil {
		t.Errorf("no model file: %v", err)
	}
	if m, _ := HorizontalKind.LoadFor(file); m == nil || m.ModelID != "file-only" {
		t.Errorf("LoadFor(file) = %v", m)
	}
}
