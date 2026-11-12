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
	"github.com/owasp-amass/asset-db/repository/sqlite3"
)

// An automatic write whose evidence disappears is retracted by the
// re-check; ai's TestRecheckAttributions covers writing it again.
func TestRecheckRetractsWhenEvidenceIsGoneOnSQLite(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "recheck.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()

	ents := seed(t, db)
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	env := map[string]string{"AMASS_AI_JOURNAL": journal}
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
		scope: &fakeScope{org: "Colgate University"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}
	if err := p.check(&et.Event{Entity: ents["colgate"], Session: sess}); err != nil {
		t.Fatal(err)
	}
	waitIdle(t, sess)

	written := func() int {
		edges, err := db.OutgoingEdges(context.Background(), ents["cr-alt"], time.Time{}, "organization")
		if err != nil {
			return 0
		}
		return len(edges)
	}
	if written() != 1 {
		t.Fatal("the pass did not write the attribution")
	}

	j := &ai.Journal{Path: journal}
	adapter := oamrepo.Adapter{Repo: db}

	// The evidence still holds: nothing is retracted.
	res, err := ai.RecheckAttributions(context.Background(), adapter, adapter, j)
	if err != nil || res.Checked != 1 || len(res.Retracted) != 0 {
		t.Fatalf("re-check with evidence: %+v, %v", res, err)
	}

	// The other domain's contact no longer shares Colgate's phone.
	edges, err := db.OutgoingEdges(context.Background(), ents["cr-alt"], time.Time{}, "phone")
	if err != nil || len(edges) != 1 {
		t.Fatalf("phone edges = %v, %v", edges, err)
	}
	if err := db.DeleteEdge(context.Background(), edges[0].ID); err != nil {
		t.Fatal(err)
	}

	res, err = ai.RecheckAttributions(context.Background(), adapter, adapter, j)
	if err != nil || len(res.Retracted) != 1 {
		t.Fatalf("re-check without evidence: %+v, %v", res, err)
	}
	if written() != 0 {
		t.Error("the retracted attribution is still stored")
	}
	entries, _ := j.OwnershipEntries()
	if entries[0].Status != ai.ProposalRetracted || entries[0].Outcome.Reviewer != ai.RecheckReviewer {
		t.Errorf("journal = %+v", entries[0])
	}
}

func waitIdle(t *testing.T, sess *fakeSession) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for sess.stats.Background() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := sess.stats.Background(); n != 0 {
		t.Fatalf("background work = %d", n)
	}
}
