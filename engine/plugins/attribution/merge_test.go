// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package attribution

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// seedDuplicates stores GlobalSign twice with the same LEI and registration,
// and Ithaka Harbors twice with only the name in common.
// touchOrgs registers organizations with the tracker as the engine does when
// it writes them during a run, so the bounded duplicate and identity drain —
// which compares the organizations the run touched, not the whole database —
// has them to compare.
func touchOrgs(tr *tracker, ents map[string]*dbt.Entity) {
	for _, e := range ents {
		tr.touch(e)
	}
}

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
	env := map[string]string{"AMASS_REVIEW_JOURNAL": journal, "AMASS_ATTRIBUTION": mode}
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
	tr := p.tracker(sess)
	if tr == nil {
		t.Fatal("attribution is off")
	}
	touchOrgs(tr, ents)
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

	awaitBackgroundZero(t, sess)

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

	entries, err := (&review.Journal{Path: journal}).DuplicateEntries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("journal = %+v, %v", entries, err)
	}
	for _, e := range entries {
		switch e.Proposal.Decision {
		case lens.GapPropose:
			if e.Status != review.ProposalApplied || e.Outcome.Reviewer != review.AutomaticReviewer ||
				e.Outcome.Merge == nil {
				t.Errorf("proposed merge: %+v", e)
			}
		default:
			if e.Status != review.ProposalPending {
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

	entries, err := (&review.Journal{Path: journal}).DuplicateEntries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("journal = %+v, %v", entries, err)
	}
	for _, e := range entries {
		if e.Status != review.ProposalPending {
			t.Errorf("journal mode left %s %s", e.Proposal.ID, e.Status)
		}
	}
}

// The incremental pass raises proposals for the organizations touched so far
// while the run is still going, records them only (never merges), and does not
// re-raise them on a later pass.
func TestIncrementalProposalsRecordWithoutMerging(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "incr.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	ents := seedDuplicates(t, db)
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
		scope: &fakeScope{org: "none"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}

	tr := &tracker{
		p: NewAttribution().(*plugin), sess: sess, mode: config.AttributionJournal,
		journal: &review.Journal{Path: journal}, orgs: map[string]*dbt.Entity{},
		allOrgs: map[string]*dbt.Entity{}, dupProcessed: map[string]struct{}{},
	}
	touchOrgs(tr, ents)

	adapter := oamrepo.Adapter{Repo: db}
	tr.incrementalProposals(context.Background(), adapter)

	// Both duplicate pairs are recorded for review, and nothing was merged.
	entries, err := (&review.Journal{Path: journal}).DuplicateEntries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("incremental pass recorded %+v, %v; want 2 proposals", entries, err)
	}
	for _, e := range entries {
		if e.Status != review.ProposalPending {
			t.Errorf("incremental pass applied %s %s; it must only record", e.Proposal.ID, e.Status)
		}
	}
	for uid, e := range ents {
		if _, err := db.FindEntityById(context.Background(), e.ID); err != nil {
			t.Errorf("incremental pass merged %s away; it must only record", uid)
		}
	}

	// A second pass re-examines nothing it already compared, so no duplicate
	// proposals pile up.
	tr.incrementalProposals(context.Background(), adapter)
	again, _ := (&review.Journal{Path: journal}).DuplicateEntries()
	if len(again) != 2 {
		t.Errorf("a second pass re-raised proposals: %d entries, want 2", len(again))
	}
}

// An undone merge restores the duplicate under a new entity ID; the next
// enumeration must still recognize the pair and not merge it again.
func TestUndoneMergeIsNotRepeated(t *testing.T) {
	db, _, journal, _ := runMergeWatcher(t, config.AttributionAuto)

	j := &review.Journal{Path: journal}
	entries, err := j.DuplicateEntries()
	if err != nil {
		t.Fatal(err)
	}

	var applied *review.DuplicateEntry
	for i, e := range entries {
		if e.Status == review.ProposalApplied {
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
	if err := j.RecordDuplicate(review.DuplicateOutcome{ProposalID: applied.Proposal.ID, Status: review.ProposalRetracted,
		Reviewer: "caffix", RestoredID: res.RestoredID}); err != nil {
		t.Fatal(err)
	}

	// A later enumeration over the same database.
	env := map[string]string{"AMASS_REVIEW_JOURNAL": journal, "AMASS_ATTRIBUTION": config.AttributionAuto}
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 10*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
		scope: &fakeScope{org: "none"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}
	tr := p.tracker(sess)
	if tr == nil {
		t.Fatal("attribution is off")
	}
	// Register the surviving and restored organizations as a run would, so the
	// drain reconsiders the pair and must honor the recorded retraction.
	survivor := applied.Proposal.SurvivorID
	for _, id := range []string{survivor, res.RestoredID} {
		if ent, err := db.FindEntityById(context.Background(), id); err == nil && ent != nil {
			tr.touch(ent)
		}
	}

	awaitBackgroundZero(t, sess)

	for _, id := range []string{survivor, res.RestoredID} {
		if _, err := db.FindEntityById(context.Background(), id); err != nil {
			t.Errorf("an undone merge was applied again: %s is gone", id)
		}
	}
}

// A merge waits while another enumeration on the engine still has work: it
// could be writing to an organization the merge would delete.
// mergeWaitTimeout is deliberately generous. The background merge watchers
// finish in well under a second on a development machine, but a loaded CI runner
// can be an order of magnitude slower, so a tight deadline turns ordinary
// slowness into a spurious failure. awaitBackgroundZero returns as soon as the
// work is done, so a healthy run never pays this timeout.
const mergeWaitTimeout = 120 * time.Second

// awaitBackgroundZero waits for every session's background work to reach zero,
// then returns; on timeout it fails with each session's remaining count.
func awaitBackgroundZero(t *testing.T, sessions ...*fakeSession) {
	t.Helper()

	deadline := time.Now().Add(mergeWaitTimeout)
	for time.Now().Before(deadline) {
		pending := false
		for _, s := range sessions {
			if s.stats.Background() != 0 {
				pending = true
				break
			}
		}
		if !pending {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}

	counts := make([]string, len(sessions))
	for i, s := range sessions {
		counts[i] = fmt.Sprintf("session[%d] background=%d", i, s.stats.Background())
	}
	t.Fatalf("merge watchers did not finish within %s: %s", mergeWaitTimeout, strings.Join(counts, ", "))
}

func TestMergesWaitForOtherSessions(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "concurrent.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()

	ents := seedDuplicates(t, db)
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	env := map[string]string{"AMASS_REVIEW_JOURNAL": journal, "AMASS_ATTRIBUTION": config.AttributionAuto}
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
	dtr := p.tracker(done)
	if dtr == nil {
		t.Fatal("attribution is off")
	}
	touchOrgs(dtr, ents)

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

	awaitBackgroundZero(t, done, busy)

	_, err1 := db.FindEntityById(context.Background(), ents["globalsign:1"].ID)
	_, err2 := db.FindEntityById(context.Background(), ents["globalsign:2"].ID)
	if (err1 == nil) == (err2 == nil) {
		t.Fatalf("want exactly one GlobalSign left after both drained: %v, %v", err1, err2)
	}
}

// A long enumeration elsewhere must not hold a drained session open: in
// journal mode nothing is written, so the proposals are recorded at once,
// and in auto mode they are recorded without being applied once the wait
// for the other sessions runs out.
func TestBusyOtherSessionsDoNotHoldADrainedSession(t *testing.T) {
	for _, mode := range []string{config.AttributionJournal, config.AttributionAuto} {
		t.Run(mode, func(t *testing.T) {
			db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "busy.db"))
			if err != nil {
				t.Fatal(err)
			}

			defer func() { _ = db.Close() }()

			ents := seedDuplicates(t, db)
			journal := filepath.Join(t.TempDir(), "review.jsonl")
			env := map[string]string{"AMASS_REVIEW_JOURNAL": journal, "AMASS_ATTRIBUTION": mode}
			p := NewAttribution().(*plugin)
			p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
			p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 10*time.Millisecond
			p.othersWait = 200 * time.Millisecond

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			session := func(total, completed int) *fakeSession {
				s := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
					scope: &fakeScope{org: "none"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}
				s.stats.WorkItemsTotal, s.stats.WorkItemsCompleted = total, completed
				return s
			}

			// The other enumeration stays busy throughout.
			if p.tracker(session(50, 10)) == nil {
				t.Fatal("attribution is off")
			}

			done := session(1, 0)
			dtr := p.tracker(done)
			if dtr == nil {
				t.Fatal("attribution is off")
			}
			touchOrgs(dtr, ents)

			awaitBackgroundZero(t, done)

			for uid, e := range ents {
				if _, err := db.FindEntityById(context.Background(), e.ID); err != nil {
					t.Errorf("merged while another enumeration was writing: %s is gone", uid)
				}
			}

			entries, err := (&review.Journal{Path: journal}).DuplicateEntries()
			if err != nil || len(entries) != 2 {
				t.Fatalf("proposals were not recorded: %+v, %v", entries, err)
			}
		})
	}
}
