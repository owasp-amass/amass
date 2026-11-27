// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"errors"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Two engines' stores on one queue share its items, each claiming what the
// other has not, and closing a store deletes the queue.
func TestQueueStoresShareTheQueue(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	q, ok := repo.(repository.WorkQueue)
	if !ok {
		t.Fatal("SQLite keeps no work queues")
	}

	ctx := context.Background()
	a, b := newQueueStore(q, "job"), newQueueStore(q, "job")
	b.fresh = 0 // read the counts every time
	t.Cleanup(func() { _ = b.Close() })
	for _, id := range []string{"1", "2", "3"} {
		if err := a.Enqueue(ctx, oam.FQDN, id); err != nil {
			t.Fatal(err)
		}
	}
	if ok, err := b.Has(ctx, "2"); err != nil || !ok {
		t.Fatalf("the other store does not see the item: %v, %v", ok, err)
	}

	first, err := a.ClaimNext(ctx, oam.FQDN, "a:FQDN", 2, 0)
	if err != nil || len(first) != 2 || first[0] != "1" {
		t.Fatalf("a claimed %v, %v", first, err)
	}
	rest, err := b.ClaimNext(ctx, oam.FQDN, "b:FQDN", 5, 0)
	if err != nil || len(rest) != 1 || rest[0] != "3" {
		t.Fatalf("b claimed %v, %v; want only what a left", rest, err)
	}
	if q, l, d, err := b.Counts(ctx, oam.FQDN); err != nil || q != 0 || l != 3 || d != 0 {
		t.Errorf("counts = %d queued, %d leased, %d done, %v", q, l, d, err)
	}
	if err := b.Ack(ctx, "1", "b:FQDN"); err == nil {
		t.Error("b acked an item a leases")
	}

	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	if q, l, d, _ := b.Counts(ctx, oam.FQDN); q+l+d != 0 {
		t.Errorf("the queue remains after closing: %d queued, %d leased, %d done", q, l, d)
	}
}

// flakyQueue counts the reads of a queue's counts, and fails acks while fail
// is set, as a slow database does.
type flakyQueue struct {
	repository.WorkQueue
	reads atomic.Int32
	fail  atomic.Bool
}

func (f *flakyQueue) CountWorkByKind(ctx context.Context, queue string) (dbt.WorkByKind, error) {
	f.reads.Add(1)
	return f.WorkQueue.CountWorkByKind(ctx, queue)
}

func (f *flakyQueue) AckWork(ctx context.Context, queue, key, owner string) error {
	if f.fail.Load() {
		return errors.New("the database did not answer in time")
	}
	return f.WorkQueue.AckWork(ctx, queue, key, owner)
}

func newFlakyQueue(t *testing.T) *flakyQueue {
	t.Helper()
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "assets.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = repo.Close() })
	q, ok := repo.(repository.WorkQueue)
	if !ok {
		t.Fatal("SQLite keeps no work queues")
	}
	return &flakyQueue{WorkQueue: q}
}

// The counts of every kind come from one read, reused for the store's fresh
// period.
func TestQueueStoreCountsReadOnce(t *testing.T) {
	f := newFlakyQueue(t)
	qs := newQueueStore(f, "job")
	t.Cleanup(func() { _ = qs.Close() })
	ctx := context.Background()
	if err := qs.Enqueue(ctx, oam.FQDN, "1"); err != nil {
		t.Fatal(err)
	}
	if err := qs.Enqueue(ctx, oam.IPAddress, "2"); err != nil {
		t.Fatal(err)
	}

	for _, atype := range []oam.AssetType{oam.FQDN, oam.IPAddress, oam.Netblock} {
		want := int64(1)
		if atype == oam.Netblock {
			want = 0
		}
		if q, _, _, err := qs.Counts(ctx, atype); err != nil || q != want {
			t.Fatalf("%s queued = %d, %v; want %d", atype, q, err, want)
		}
	}
	if n := f.reads.Load(); n != 1 {
		t.Errorf("the counts were read %d times, want once", n)
	}

	if err := qs.Enqueue(ctx, oam.FQDN, "3"); err != nil {
		t.Fatal(err)
	}
	if q, _, _, err := qs.Counts(ctx, oam.FQDN); err != nil || q != 1 {
		t.Errorf("within the fresh period, FQDN queued = %d, %v; want the reused 1", q, err)
	}
	qs.mu.Lock()
	qs.fresh = 0
	qs.mu.Unlock()
	if q, _, _, err := qs.Counts(ctx, oam.FQDN); err != nil || q != 2 {
		t.Errorf("after the fresh period, FQDN queued = %d, %v; want 2", q, err)
	}
	if n := f.reads.Load(); n != 2 {
		t.Errorf("the counts were read %d times, want twice", n)
	}
}

// A finished item whose ack fails is acked again, so its lease is not
// renewed for good.
func TestQueueStoreRetriesFailedAcks(t *testing.T) {
	f := newFlakyQueue(t)
	qs := newQueueStore(f, "job")
	qs.fresh = 0 // read the counts every time
	t.Cleanup(func() { _ = qs.Close() })
	ctx := context.Background()
	if err := qs.Enqueue(ctx, oam.FQDN, "1"); err != nil {
		t.Fatal(err)
	}
	if got, err := qs.ClaimNext(ctx, oam.FQDN, "w:FQDN", 1, 0); err != nil || len(got) != 1 {
		t.Fatalf("claimed %v, %v", got, err)
	}

	f.fail.Store(true)
	if err := qs.Ack(ctx, "1", ""); err == nil {
		t.Fatal("the ack did not fail")
	}
	if _, l, _, err := qs.Counts(ctx, oam.FQDN); err != nil || l != 1 {
		t.Fatalf("leased = %d, %v; want the item still leased", l, err)
	}

	f.fail.Store(false)
	qs.retryAcks(time.Second)
	if _, l, d, err := qs.Counts(ctx, oam.FQDN); err != nil || l != 0 || d != 1 {
		t.Errorf("after the retry: %d leased, %d done, %v; want it done", l, d, err)
	}
	qs.mu.Lock()
	left := len(qs.unacked)
	qs.mu.Unlock()
	if left != 0 {
		t.Errorf("%d acks are still waiting", left)
	}
}
