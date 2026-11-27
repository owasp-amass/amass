// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// backlogStore keeps a backlog's items by entity ID: the session's local
// backlog database, or a work queue in the Asset Database.
type backlogStore interface {
	Has(ctx context.Context, entityID string) (bool, error)
	Enqueue(ctx context.Context, atype oam.AssetType, entityID string) error
	// ClaimNext leases up to n items, oldest first; a ttl of zero or less
	// leases them until they are acked or released.
	ClaimNext(ctx context.Context, atype oam.AssetType, owner string, n int, ttl time.Duration) ([]string, error)
	Ack(ctx context.Context, entityID, owner string) error
	Release(ctx context.Context, entityID, owner string) error
	Counts(ctx context.Context, atype oam.AssetType) (queued, leased, done int64, err error)
	Close() error
}

// queueLeaseTTL is how long a claim on the database's work queue lasts
// unless renewed. A claim without a time to live is renewed every third of
// it while the session lives, so it lasts until acked or released, and an
// engine that stops leaves its items for the queue's other workers.
const queueLeaseTTL = 2 * time.Minute

// queueCountsFresh is how long the queue's counts are reused, so a pump
// asking about every kind of asset in turn, and every completion waking it,
// read the queue once a second at most.
const queueCountsFresh = time.Second

// queueStore is a backlog kept in the Asset Database's work queue, which
// the engines sharing the database can work on together.
type queueStore struct {
	q     repository.WorkQueue
	queue string

	mu     sync.Mutex
	owners map[string]bool // the owners whose leases are renewed
	// unacked are finished items whose ack failed (a slow database), by
	// key, with the owner given; renew retries them, since their leases
	// would otherwise be renewed for good and the run would never end.
	unacked map[string]string
	// counts are the queue's counts by kind, read at countsAt and reused
	// for fresh.
	counts   dbt.WorkByKind
	countsAt time.Time
	fresh    time.Duration
	stop     chan struct{}
	wg       sync.WaitGroup
	once     sync.Once
	// keep leaves the queue in the database on Close, for the job's other
	// workers.
	keep atomic.Bool
}

func newQueueStore(q repository.WorkQueue, queue string) *queueStore {
	qs := &queueStore{q: q, queue: queue, owners: map[string]bool{}, unacked: map[string]string{},
		fresh: queueCountsFresh, stop: make(chan struct{})}
	qs.wg.Add(1)
	go qs.renew(queueLeaseTTL / 3)
	return qs
}

// renew retries the acks that failed, then extends the leases of the owners
// that claimed without a time to live, every interval until the store
// closes.
func (qs *queueStore) renew(interval time.Duration) {
	defer qs.wg.Done()
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-qs.stop:
			return
		case <-t.C:
		}

		qs.retryAcks(interval)
		qs.mu.Lock()
		owners := make([]string, 0, len(qs.owners))
		for o := range qs.owners {
			owners = append(owners, o)
		}
		qs.mu.Unlock()

		for _, o := range owners {
			ctx, cancel := context.WithTimeout(context.Background(), interval)
			_, _ = qs.q.RenewWork(ctx, qs.queue, o, queueLeaseTTL)
			cancel()
		}
	}
}

// retryAcks acks again the finished items whose ack failed, giving each try
// at most timeout. An item no longer leased (its lease expired and another
// worker took it) is dropped.
func (qs *queueStore) retryAcks(timeout time.Duration) {
	qs.mu.Lock()
	pending := make(map[string]string, len(qs.unacked))
	for k, o := range qs.unacked {
		pending[k] = o
	}
	qs.mu.Unlock()

	for key, owner := range pending {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		err := qs.q.AckWork(ctx, qs.queue, key, owner)
		cancel()
		if err == nil || errors.Is(err, dbt.ErrWorkNotLeased) {
			qs.mu.Lock()
			delete(qs.unacked, key)
			qs.mu.Unlock()
		}
	}
}

func (qs *queueStore) Has(ctx context.Context, entityID string) (bool, error) {
	found, err := qs.q.HasWork(ctx, qs.queue, entityID)
	return found[entityID], err
}

func (qs *queueStore) Enqueue(ctx context.Context, atype oam.AssetType, entityID string) error {
	return qs.q.EnqueueWork(ctx, qs.queue, string(atype), entityID)
}

func (qs *queueStore) ClaimNext(ctx context.Context, atype oam.AssetType, owner string, n int,
	ttl time.Duration) ([]string, error) {
	if n <= 0 {
		return nil, nil
	}
	if owner == "" {
		owner = "default"
	}
	if ttl <= 0 {
		ttl = queueLeaseTTL
		qs.mu.Lock()
		qs.owners[owner] = true
		qs.mu.Unlock()
	}
	return qs.q.ClaimWork(ctx, qs.queue, string(atype), owner, n, ttl)
}

func (qs *queueStore) Ack(ctx context.Context, entityID, owner string) error {
	err := qs.q.AckWork(ctx, qs.queue, entityID, owner)
	if err != nil && !errors.Is(err, dbt.ErrWorkNotLeased) {
		qs.mu.Lock()
		qs.unacked[entityID] = owner
		qs.mu.Unlock()
	}
	return err
}

func (qs *queueStore) Release(ctx context.Context, entityID, owner string) error {
	return qs.q.ReleaseWork(ctx, qs.queue, entityID, owner)
}

// Counts reads the counts of every kind at once and reuses them for the
// store's fresh period.
func (qs *queueStore) Counts(ctx context.Context, atype oam.AssetType) (queued, leased, done int64, err error) {
	qs.mu.Lock()
	byKind := qs.counts
	fresh := !qs.countsAt.IsZero() && time.Since(qs.countsAt) < qs.fresh
	qs.mu.Unlock()
	if !fresh {
		read := time.Now()
		if byKind, err = qs.q.CountWorkByKind(ctx, qs.queue); err != nil {
			return 0, 0, 0, err
		}
		qs.mu.Lock()
		qs.counts, qs.countsAt = byKind, read
		qs.mu.Unlock()
	}

	c := byKind[string(atype)]
	return c.Queued, c.Leased, c.Done, nil
}

// Close stops renewing the leases and deletes the queue, unless it is kept.
func (qs *queueStore) Close() error {
	var err error
	qs.once.Do(func() {
		close(qs.stop)
		qs.wg.Wait()
		if qs.keep.Load() {
			return
		}

		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		err = qs.q.DeleteQueue(ctx, qs.queue)
	})
	return err
}
