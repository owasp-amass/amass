// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"path/filepath"
	"time"

	bdb "github.com/owasp-amass/amass/v5/engine/sessions/backlogdb"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

var (
	ErrNoEntitiesClaimed = errors.New("no entities claimed")
)

// sessionBacklog is the per-session durable backlog used for dedupe + capacity-aware dispatch.
// It provides claim/lease semantics: items claimed are "in-flight" until Ack() or Release().
type sessionBacklog struct {
	session  *Session
	db       backlogStore
	owner    string
	leaseTTL time.Duration
}

var _ backlogStore = (*bdb.BacklogDB)(nil)

// newSessionBacklog keeps the session's backlog in the Asset Database's work
// queue, named by the session's job, when the database keeps work queues
// (PostgreSQL and SQLite), and otherwise in a local database in the
// session's temporary directory.
func newSessionBacklog(s *Session) (*sessionBacklog, error) {
	if s == nil {
		return nil, errors.New("session is nil")
	}
	if q, ok := s.DB().(repository.WorkQueue); ok {
		return newBacklog(s, newQueueStore(q, s.jobQueue())), nil
	}
	return newLocalBacklog(s)
}

// newLocalBacklog keeps the session's backlog in its temporary directory.
func newLocalBacklog(s *Session) (*sessionBacklog, error) {
	dbfile := filepath.Join(s.TmpDir(), "backlog.db")

	db, err := bdb.NewBacklogDB(dbfile, bdb.Options{
		BusyTimeout: 30 * time.Second,
		JournalMode: "WAL",
	})
	if err != nil {
		return nil, err
	}

	return newBacklog(s, db), nil
}

func newBacklog(s *Session, store backlogStore) *sessionBacklog {
	return &sessionBacklog{
		session: s,
		db:      store,
		// The owner is stable per session; the dispatcher is its only consumer.
		owner:    s.ID().String(),
		leaseTTL: 45 * time.Second, // starting point; tune to pipeline latency
	}
}

// keepQueue leaves the backlog's work queue in the database when the
// backlog closes, for the job's other workers.
func (sb *sessionBacklog) keepQueue() {
	if sb == nil {
		return
	}
	if qs, ok := sb.db.(*queueStore); ok {
		qs.keep.Store(true)
	}
}

func (sb *sessionBacklog) Close() error {
	if sb == nil || sb.db == nil {
		return nil
	}
	return sb.db.Close()
}

// SetLeaseTTL overrides the default lease TTL used by ClaimNext.
// TTL should exceed typical end-to-end pipeline latency, or use Release on backpressure.
// A TTL of zero leases claimed entities until they are acked or released (in the
// database's work queue, while the session lives).
func (sb *sessionBacklog) SetLeaseTTL(ttl time.Duration) {
	if ttl >= 0 {
		sb.leaseTTL = ttl
	}
}

// Has reports whether this entity ID has ever been enqueued into the backlog (any state).
func (sb *sessionBacklog) Has(e *dbt.Entity) bool {
	if sb == nil || sb.db == nil || e == nil || e.ID == "" {
		return false
	}

	ctx, cancel := context.WithTimeout(sb.session.Ctx(), 2*time.Second)
	defer cancel()

	ok, err := sb.db.Has(ctx, e.ID)
	return err == nil && ok
}

// Enqueue adds the entity to the backlog in queued state. An entity already in the
// backlog is not duplicated: one already done returns to the queued state, for
// another look, and one queued or leased is left as it is, so it is never worked
// on twice at once.
func (sb *sessionBacklog) Enqueue(e *dbt.Entity) error {
	if sb == nil || sb.db == nil {
		return errors.New("backlog is nil")
	}
	if e == nil {
		return errors.New("entity is nil")
	}
	if e.ID == "" {
		return errors.New("entity ID is empty")
	}
	if e.Asset == nil {
		return errors.New("asset is nil")
	}

	atype := e.Asset.AssetType()
	if atype == "" {
		return errors.New("asset type is empty")
	}

	ctx, cancel := context.WithTimeout(sb.session.Ctx(), 5*time.Second)
	defer cancel()

	return sb.db.Enqueue(ctx, atype, e.ID)
}

// ClaimNext claims up to num entities of the given asset type from the backlog and returns
// the corresponding entities loaded from the asset DB. Claimed items are leased (in-flight)
// until Ack() or Release().
//
// An entity ID present in the backlog but missing from the asset DB is acked, so it
// is not claimed again, and left out of the results.
func (sb *sessionBacklog) ClaimNext(atype oam.AssetType, num int) ([]*dbt.Entity, error) {
	if sb == nil || sb.db == nil {
		return nil, errors.New("backlog is nil")
	}
	if num <= 0 {
		return nil, ErrNoEntitiesClaimed
	}

	ctx, cancel := context.WithTimeout(sb.session.Ctx(), 5*time.Second)
	defer cancel()

	owner := sb.owner + ":" + string(atype)

	claims, err := sb.db.ClaimNext(ctx, atype, owner, num, sb.leaseTTL)
	if err != nil {
		return nil, err
	}
	if len(claims) == 0 {
		return nil, ErrNoEntitiesClaimed
	}

	results := make([]*dbt.Entity, 0, len(claims))
	for _, id := range claims {
		cctx, ccancel := context.WithTimeout(sb.session.Ctx(), 5*time.Second)
		ent, ferr := sb.session.DB().FindEntityById(cctx, id)
		ccancel()

		if ferr == nil && ent != nil {
			results = append(results, ent)
			continue
		}

		// Entity missing from asset DB: ack the entity so it doesn't get claimed again.
		actx, acancel := context.WithTimeout(sb.session.Ctx(), 5*time.Second)
		_ = sb.db.Ack(actx, id, owner)
		acancel()
	}

	if len(results) == 0 {
		return nil, ErrNoEntitiesClaimed
	}
	return results, nil
}

// Ack marks a claimed (leased) entity as completed (done).
// If you want strict ownership enforcement, pass enforceOwner=true.
func (sb *sessionBacklog) Ack(e *dbt.Entity, enforceOwner bool) error {
	if sb == nil || sb.db == nil {
		return errors.New("backlog is nil")
	}
	if e == nil || e.ID == "" {
		return errors.New("entity is nil or ID is empty")
	}

	ctx, cancel := context.WithTimeout(sb.session.Ctx(), 5*time.Second)
	defer cancel()

	owner := ""
	if enforceOwner && e.Asset != nil {
		owner = sb.owner + ":" + string(e.Asset.AssetType())
	}

	return sb.db.Ack(ctx, e.ID, owner)
}

// Release returns a claimed (leased) entity back to queued state.
// Use this when you successfully claimed an entity but could not enqueue it to a pipeline
// (e.g., due to backpressure), so it can be claimed again quickly.
//
// If you want strict ownership enforcement, pass enforceOwner=true.
func (sb *sessionBacklog) Release(e *dbt.Entity, atype oam.AssetType, enforceOwner bool) error {
	if sb == nil || sb.db == nil {
		return errors.New("backlog is nil")
	}
	if e == nil || e.ID == "" {
		return errors.New("entity is nil or ID is empty")
	}

	ctx, cancel := context.WithTimeout(sb.session.Ctx(), 5*time.Second)
	defer cancel()

	owner := ""
	if enforceOwner {
		owner = sb.owner + ":" + string(atype)
	}

	return sb.db.Release(ctx, e.ID, owner)
}

func (sb *sessionBacklog) Counts(atype oam.AssetType) (queued, leased, done int64, err error) {
	if sb == nil || sb.db == nil {
		return 0, 0, 0, errors.New("backlog is nil")
	}

	ctx, cancel := context.WithTimeout(sb.session.Ctx(), 3*time.Second)
	defer cancel()

	return sb.db.Counts(ctx, atype)
}
