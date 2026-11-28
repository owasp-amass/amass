// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package attribution

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
)

// A strong merge proposal is applied while the run goes on once neither
// organization is being written to; until then its duplicate waits, and a
// pair a person must decide is never merged.
func TestQuietMergesWhileTheRunGoesOn(t *testing.T) {
	for _, mode := range []string{config.AttributionAuto, config.AttributionJournal} {
		t.Run(mode, func(t *testing.T) {
			db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "quiet.db"))
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = db.Close() }()

			ctx := context.Background()
			ents := seedDuplicates(t, db)
			journal := filepath.Join(t.TempDir(), "review.jsonl")
			sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
				scope: &fakeScope{org: "none"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}
			p := NewAttribution().(*plugin)
			p.mergeQuiet = time.Hour
			tr := &tracker{p: p, sess: sess, mode: mode, journal: review.OpenJournal(journal, db),
				orgs: map[string]*dbt.Entity{}, allOrgs: map[string]*dbt.Entity{}, dupProcessed: map[string]struct{}{}}
			touchOrgs(tr, ents)

			adapter := oamrepo.Adapter{Repo: db}
			tr.incrementalProposals(ctx, adapter)

			// the organizations were just written: nothing merges yet
			waiting := tr.quietMerges(ctx, adapter)
			for uid, e := range ents {
				if _, err := db.FindEntityById(ctx, e.ID); err != nil {
					t.Fatalf("%s was merged away while it was being written to", uid)
				}
			}
			if mode == config.AttributionJournal {
				if len(waiting) != 0 {
					t.Errorf("journal mode holds %v back for merges it never applies", waiting)
				}
				return
			}
			if len(waiting) != 1 {
				t.Fatalf("waiting duplicates = %v, want the one strong pair's", waiting)
			}
			for _, uid := range []string{"ithaka:1", "ithaka:2"} {
				if _, wait := waiting[ents[uid].ID]; wait {
					t.Errorf("a name-only pair's %s waits for a merge it never gets", uid)
				}
			}

			// once nothing has been written for the quiet time, the strong pair merges
			p.mergeQuiet = 0
			if waiting = tr.quietMerges(ctx, adapter); len(waiting) != 0 {
				t.Errorf("still waiting: %v", waiting)
			}
			_, err1 := db.FindEntityById(ctx, ents["globalsign:1"].ID)
			_, err2 := db.FindEntityById(ctx, ents["globalsign:2"].ID)
			if (err1 == nil) == (err2 == nil) {
				t.Fatalf("want exactly one of the strong pair left: %v, %v", err1, err2)
			}
			for _, uid := range []string{"ithaka:1", "ithaka:2"} {
				if _, err := db.FindEntityById(ctx, ents[uid].ID); err != nil {
					t.Errorf("a name-only pair was merged automatically: %s is gone", uid)
				}
			}

			gone := ents["globalsign:1"].ID
			if err2 != nil {
				gone = ents["globalsign:2"].ID
			}
			if _, tracked := tr.allOrgs[gone]; tracked {
				t.Error("the merged duplicate is still tracked")
			}

			entries, err := review.OpenJournal(journal, db).DuplicateEntries()
			if err != nil {
				t.Fatal(err)
			}
			applied := 0
			for _, e := range entries {
				if e.Status == review.ProposalApplied && e.Outcome != nil && e.Outcome.Reviewer == review.AutomaticReviewer {
					applied++
				}
			}
			if applied != 1 {
				t.Errorf("%d merges recorded as applied, want 1: %+v", applied, entries)
			}
		})
	}
}
