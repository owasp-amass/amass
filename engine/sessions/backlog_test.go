// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// backlogStores are the stores a session backlog is tested on.
var backlogStores = []string{"queue", "local"}

// backlogSession is a session on SQLite with its backlog in the database's
// work queue, or in the session's local backlog database.
func backlogSession(t *testing.T, store string) (*Session, *sessionBacklog) {
	t.Helper()

	dir := t.TempDir()
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(dir, "assets.db"))
	if err != nil {
		t.Fatalf("the database was not opened: %v", err)
	}
	t.Cleanup(func() { _ = repo.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	s := &Session{id: uuid.New(), ctx: ctx, db: repo, tmpdir: dir}
	sb, err := newSessionBacklog(s)
	if store == "local" {
		_ = sb.Close()
		sb, err = newLocalBacklog(s)
	}
	if err != nil {
		t.Fatalf("the backlog was not created: %v", err)
	}
	if qs, ok := sb.db.(*queueStore); ok {
		qs.fresh = 0 // the tests read the counts right after each change
	}
	t.Cleanup(func() { _ = sb.Close() })
	return s, sb
}

func fqdnEntity(t *testing.T, s *Session, name string) *dbt.Entity {
	t.Helper()

	ent, err := s.DB().CreateAsset(context.Background(), &oamdns.FQDN{Name: name})
	if err != nil {
		t.Fatalf("%s was not stored: %v", name, err)
	}
	return ent
}

func TestSessionBacklogEnqueueRejectsIncompleteEntities(t *testing.T) {
	for _, store := range backlogStores {
		t.Run(store, func(t *testing.T) { testSessionBacklogEnqueueRejectsIncompleteEntities(t, store) })
	}
}

func testSessionBacklogEnqueueRejectsIncompleteEntities(t *testing.T, store string) {
	_, sb := backlogSession(t, store)

	for name, e := range map[string]*dbt.Entity{
		"nil":      nil,
		"no ID":    {Asset: &oamdns.FQDN{Name: "www.example.com"}},
		"no asset": {ID: "1"},
	} {
		if err := sb.Enqueue(e); err == nil {
			t.Errorf("an entity with %s was enqueued", name)
		}
	}
	if sb.Has(nil) || sb.Has(&dbt.Entity{}) {
		t.Error("Has reported an entity without an ID")
	}

	var nilBacklog *sessionBacklog
	if err := nilBacklog.Enqueue(&dbt.Entity{ID: "1"}); err == nil {
		t.Error("a nil backlog accepted an entity")
	}
	if _, err := nilBacklog.ClaimNext(oam.FQDN, 1); err == nil {
		t.Error("a nil backlog handed out a claim")
	}
}

func TestSessionBacklogClaimsTheStoredEntities(t *testing.T) {
	for _, store := range backlogStores {
		t.Run(store, func(t *testing.T) { testSessionBacklogClaimsTheStoredEntities(t, store) })
	}
}

func testSessionBacklogClaimsTheStoredEntities(t *testing.T, store string) {
	s, sb := backlogSession(t, store)
	sb.SetLeaseTTL(0)

	www := fqdnEntity(t, s, "www.example.com")
	api := fqdnEntity(t, s, "api.example.com")
	for _, e := range []*dbt.Entity{www, api} {
		if err := sb.Enqueue(e); err != nil {
			t.Fatal(err)
		}
	}
	if !sb.Has(www) || !sb.Has(api) {
		t.Fatal("the enqueued entities are not in the backlog")
	}

	if _, err := sb.ClaimNext(oam.FQDN, 0); !errors.Is(err, ErrNoEntitiesClaimed) {
		t.Errorf("a claim of zero gave %v", err)
	}
	if _, err := sb.ClaimNext(oam.IPAddress, 5); !errors.Is(err, ErrNoEntitiesClaimed) {
		t.Errorf("a claim of another type gave %v", err)
	}

	claimed, err := sb.ClaimNext(oam.FQDN, 5)
	if err != nil || len(claimed) != 2 {
		t.Fatalf("claimed %v, %v", claimed, err)
	}
	if claimed[0].ID != www.ID || claimed[0].Asset.Key() != "www.example.com" {
		t.Errorf("the first claim is %v, want the entity loaded from the database", claimed[0].Asset)
	}
	if q, l, d, err := sb.Counts(oam.FQDN); err != nil || q != 0 || l != 2 || d != 0 {
		t.Errorf("counts after the claim = %d queued, %d leased, %d done, %v", q, l, d, err)
	}

	// Releasing returns an entity to the queue, and acking finishes it.
	if err := sb.Release(api, oam.FQDN, true); err != nil {
		t.Fatal(err)
	}
	if err := sb.Ack(www, true); err != nil {
		t.Fatal(err)
	}
	if q, l, d, _ := sb.Counts(oam.FQDN); q != 1 || l != 0 || d != 1 {
		t.Errorf("counts after release and ack = %d queued, %d leased, %d done", q, l, d)
	}

	again, err := sb.ClaimNext(oam.FQDN, 5)
	if err != nil || len(again) != 1 || again[0].ID != api.ID {
		t.Errorf("the released entity was not claimed again: %v, %v", again, err)
	}
	// An owned ack of an entity that is not leased fails.
	if err := sb.Ack(www, true); err == nil {
		t.Error("an owned ack of a finished entity succeeded")
	}
}

func TestSessionBacklogAcksEntitiesMissingFromTheDatabase(t *testing.T) {
	for _, store := range backlogStores {
		t.Run(store, func(t *testing.T) { testSessionBacklogAcksEntitiesMissingFromTheDatabase(t, store) })
	}
}

func testSessionBacklogAcksEntitiesMissingFromTheDatabase(t *testing.T, store string) {
	s, sb := backlogSession(t, store)

	gone := &dbt.Entity{ID: "999999", Asset: &oamdns.FQDN{Name: "gone.example.com"}}
	if err := sb.Enqueue(gone); err != nil {
		t.Fatal(err)
	}
	www := fqdnEntity(t, s, "www.example.com")
	if err := sb.Enqueue(www); err != nil {
		t.Fatal(err)
	}

	claimed, err := sb.ClaimNext(oam.FQDN, 5)
	if err != nil || len(claimed) != 1 || claimed[0].ID != www.ID {
		t.Fatalf("claimed %v, %v; want only the stored entity", claimed, err)
	}
	if q, l, d, _ := sb.Counts(oam.FQDN); q != 0 || l != 1 || d != 1 {
		t.Errorf("counts = %d queued, %d leased, %d done; the missing entity should be done", q, l, d)
	}

	// With only missing entities left, nothing is claimed.
	if err := sb.Enqueue(&dbt.Entity{ID: "888888", Asset: &oamdns.FQDN{Name: "gone2.example.com"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := sb.ClaimNext(oam.FQDN, 5); !errors.Is(err, ErrNoEntitiesClaimed) {
		t.Errorf("a claim of only missing entities gave %v", err)
	}
}
