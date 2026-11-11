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
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// seedDuplicates stores GlobalSign twice with the same LEI and registration,
// and Ithaka Harbors twice with only the name in common.
func seedDuplicates(t *testing.T, db repository.Repository) map[string]*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	ents := map[string]*dbt.Entity{}
	lei, err := db.CreateAsset(ctx, &general.Identifier{UniqueID: "lei:875500H0WKURA9XATD59",
		ID: "875500H0WKURA9XATD59", Type: general.LEICode})
	if err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"globalsign:1", "globalsign:2"} {
		o, err := db.CreateAsset(ctx, &oamorg.Organization{ID: uid, Name: "globalsign", Jurisdiction: "BE",
			RegistrationID: "0459134256"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.CreateEdge(ctx, &dbt.Edge{FromEntity: o, ToEntity: lei,
			Relation: &general.SimpleRelation{Name: "id"}}); err != nil {
			t.Fatal(err)
		}
		ents[uid] = o
	}
	for _, uid := range []string{"ithaka:1", "ithaka:2"} {
		o, err := db.CreateAsset(ctx, &oamorg.Organization{ID: uid, Name: "ithaka harbors"})
		if err != nil {
			t.Fatal(err)
		}
		ents[uid] = o
	}

	return ents
}

func runMergeWatcher(t *testing.T, mode string) (repository.Repository, map[string]*dbt.Entity, string, *fakeSession) {
	t.Helper()

	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "merges.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	ents := seedDuplicates(t, db)
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	env := map[string]string{"AMASS_AI_JOURNAL": journal, "AMASS_AI_ATTRIBUTION": mode}
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 10*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
		scope: &fakeScope{org: "none"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}

	// The enumeration is still busy: the watcher must wait.
	sess.stats.Lock()
	sess.stats.WorkItemsTotal, sess.stats.WorkItemsCompleted = 10, 3
	sess.stats.Unlock()
	if p.tracker(sess) == nil {
		t.Fatal("attribution is off")
	}
	if n := sess.stats.Background(); n != 1 {
		t.Fatalf("background work = %d, want the merge watcher counted", n)
	}

	time.Sleep(100 * time.Millisecond)
	if _, err := db.FindEntityById(context.Background(), ents["globalsign:2"].ID); err != nil {
		t.Fatal("merged while the enumeration still had work")
	}
	if _, err := db.FindEntityById(context.Background(), ents["globalsign:1"].ID); err != nil {
		t.Fatal("merged while the enumeration still had work")
	}

	// Only the watcher's own unit is left.
	sess.stats.Lock()
	sess.stats.WorkItemsTotal, sess.stats.WorkItemsCompleted = 11, 10
	sess.stats.Unlock()

	deadline := time.Now().Add(20 * time.Second)
	for sess.stats.Background() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := sess.stats.Background(); n != 0 {
		t.Fatalf("the merge watcher did not finish: background work = %d", n)
	}

	return db, ents, journal, sess
}

func TestDuplicatesAreMergedWhenTheEnumerationDrains(t *testing.T) {
	db, ents, journal, _ := runMergeWatcher(t, config.AttributionAuto)

	_, err1 := db.FindEntityById(context.Background(), ents["globalsign:1"].ID)
	_, err2 := db.FindEntityById(context.Background(), ents["globalsign:2"].ID)
	if (err1 == nil) == (err2 == nil) {
		t.Fatalf("want exactly one GlobalSign left: %v, %v", err1, err2)
	}
	for _, uid := range []string{"ithaka:1", "ithaka:2"} {
		if _, err := db.FindEntityById(context.Background(), ents[uid].ID); err != nil {
			t.Errorf("a name-only pair was merged automatically: %s is gone", uid)
		}
	}

	entries, err := (&ai.Journal{Path: journal}).DuplicateEntries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("journal = %+v, %v", entries, err)
	}
	for _, e := range entries {
		switch e.Proposal.Decision {
		case ai.GapPropose:
			if e.Status != ai.ProposalApplied || e.Outcome.Reviewer != ai.AutomaticReviewer || e.Outcome.Merge == nil {
				t.Errorf("proposed merge: %+v", e)
			}
		default:
			if e.Status != ai.ProposalPending {
				t.Errorf("review merge was %s, want pending", e.Status)
			}
		}
	}
}

func TestDuplicatesAreOnlyRecordedInJournalMode(t *testing.T) {
	db, ents, journal, _ := runMergeWatcher(t, config.AttributionJournal)

	for uid, e := range ents {
		if _, err := db.FindEntityById(context.Background(), e.ID); err != nil {
			t.Errorf("journal mode merged: %s is gone", uid)
		}
	}

	entries, err := (&ai.Journal{Path: journal}).DuplicateEntries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("journal = %+v, %v", entries, err)
	}
	for _, e := range entries {
		if e.Status != ai.ProposalPending {
			t.Errorf("journal mode left %s %s", e.Proposal.ID, e.Status)
		}
	}
}

// An undone merge restores the duplicate under a new entity ID; the next
// enumeration must still recognize the pair and not merge it again.
func TestUndoneMergeIsNotRepeated(t *testing.T) {
	db, _, journal, _ := runMergeWatcher(t, config.AttributionAuto)

	j := &ai.Journal{Path: journal}
	entries, err := j.DuplicateEntries()
	if err != nil {
		t.Fatal(err)
	}

	var applied *ai.DuplicateEntry
	for i, e := range entries {
		if e.Status == ai.ProposalApplied {
			applied = &entries[i]
		}
	}
	if applied == nil {
		t.Fatalf("nothing was merged: %+v", entries)
	}

	adapter := oamrepo.Adapter{Repo: db}
	res, err := adapter.UnmergeOrganizations(context.Background(), *applied.Outcome.Merge)
	if err != nil {
		t.Fatal(err)
	}
	if err := j.RecordDuplicate(ai.DuplicateOutcome{ProposalID: applied.Proposal.ID, Status: ai.ProposalRetracted,
		Reviewer: "caffix", RestoredID: res.RestoredID}); err != nil {
		t.Fatal(err)
	}

	// A later enumeration over the same database.
	env := map[string]string{"AMASS_AI_JOURNAL": journal, "AMASS_AI_ATTRIBUTION": config.AttributionAuto}
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 10*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
		scope: &fakeScope{org: "none"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}
	if p.tracker(sess) == nil {
		t.Fatal("attribution is off")
	}

	deadline := time.Now().Add(20 * time.Second)
	for sess.stats.Background() != 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}

	survivor := applied.Proposal.SurvivorID
	for _, id := range []string{survivor, res.RestoredID} {
		if _, err := db.FindEntityById(context.Background(), id); err != nil {
			t.Errorf("an undone merge was applied again: %s is gone", id)
		}
	}
}

// A merge waits while another enumeration on the engine still has work: it
// could be writing to an organization the merge would delete.
func TestMergesWaitForOtherSessions(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	ents := seedDuplicates(t, db)
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	env := map[string]string{"AMASS_AI_JOURNAL": journal, "AMASS_AI_ATTRIBUTION": config.AttributionAuto}
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 10*time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	session := func(total, completed int) *fakeSession {
		s := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
			scope: &fakeScope{org: "none"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}
		s.stats.WorkItemsTotal, s.stats.WorkItemsCompleted = total, completed
		return s
	}

	// The other enumeration starts first and is still busy.
	busy := session(50, 10)
	if p.tracker(busy) == nil {
		t.Fatal("attribution is off")
	}
	done := session(1, 0)
	if p.tracker(done) == nil {
		t.Fatal("attribution is off")
	}

	time.Sleep(200 * time.Millisecond)
	for _, uid := range []string{"globalsign:1", "globalsign:2"} {
		if _, err := db.FindEntityById(context.Background(), ents[uid].ID); err != nil {
			t.Fatalf("merged while another enumeration still had work: %s is gone", uid)
		}
	}
	if n := done.stats.Background(); n != 1 {
		t.Fatalf("the drained session's watcher stopped waiting: background work = %d", n)
	}

	// The other enumeration drains; only its own watcher is left.
	busy.stats.Lock()
	busy.stats.WorkItemsTotal, busy.stats.WorkItemsCompleted = 11, 10
	busy.stats.Unlock()

	deadline := time.Now().Add(20 * time.Second)
	for (done.stats.Background() != 0 || busy.stats.Background() != 0) && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if done.stats.Background() != 0 || busy.stats.Background() != 0 {
		t.Fatal("the merge watchers did not finish")
	}

	_, err1 := db.FindEntityById(context.Background(), ents["globalsign:1"].ID)
	_, err2 := db.FindEntityById(context.Background(), ents["globalsign:2"].ID)
	if (err1 == nil) == (err2 == nil) {
		t.Fatalf("want exactly one GlobalSign left after both drained: %v, %v", err1, err2)
	}
}
