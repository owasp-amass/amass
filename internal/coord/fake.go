// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package coord

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
)

// FakeStore keeps a journal in memory, as the Asset Database does, for
// tests. It is a repository.Repository only in name: its other methods are
// not implemented.
type FakeStore struct {
	repository.Repository
	mu   sync.Mutex
	recs []*dbt.JournalRecord
	// Reads records where each read started.
	Reads []int64
}

// AppendJournal implements Store.
func (f *FakeStore) AppendJournal(_ context.Context, rec *dbt.JournalRecord) (*dbt.JournalRecord, error) {
	if err := rec.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	out := *rec
	if len(out.Data) == 0 {
		out.Data = []byte("{}")
	}
	out.Seq, out.At = int64(len(f.recs)+1), time.Now()
	f.recs = append(f.recs, &out)
	return &out, nil
}

// ReadJournal implements Store.
func (f *FakeStore) ReadJournal(ctx context.Context, topic string, after int64, limit int) ([]*dbt.JournalRecord, error) {
	return f.ReadJournalFiltered(ctx, topic, dbt.JournalFilter{}, after, limit)
}

// ReadJournalFiltered implements Store.
func (f *FakeStore) ReadJournalFiltered(_ context.Context, topic string, flt dbt.JournalFilter, after int64,
	limit int) ([]*dbt.JournalRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.Reads = append(f.Reads, after)
	var out []*dbt.JournalRecord
	for _, r := range f.recs {
		if r.Topic == topic && r.Seq > after && (flt.Key == "" || r.Key == flt.Key) &&
			(len(flt.Kinds) == 0 || slices.Contains(flt.Kinds, r.Kind)) {
			out = append(out, r)
			if limit > 0 && len(out) == limit {
				break
			}
		}
	}
	return out, nil
}

// Records returns every record appended, in order.
func (f *FakeStore) Records() []*dbt.JournalRecord {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*dbt.JournalRecord(nil), f.recs...)
}

// FakeLeases keeps leases in memory, as the Asset Database does, for tests.
type FakeLeases struct {
	mu     sync.Mutex
	leases map[string]dbt.Lease
}

// AcquireLease implements LeaseStore.
func (f *FakeLeases) AcquireLease(_ context.Context, name, holder string, ttl time.Duration,
	data json.RawMessage) (*dbt.Lease, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.leases == nil {
		f.leases = map[string]dbt.Lease{}
	}
	now := time.Now()
	if l, ok := f.leases[name]; ok && l.Holder != holder && l.ExpiresAt.After(now) {
		return &l, false, nil
	}
	l := dbt.Lease{Name: name, Holder: holder, AcquiredAt: now, ExpiresAt: now.Add(ttl), Data: data}
	f.leases[name] = l
	return &l, true, nil
}

// FindLease implements LeaseStore.
func (f *FakeLeases) FindLease(_ context.Context, name string) (*dbt.Lease, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.leases[name]; ok && l.ExpiresAt.After(time.Now()) {
		return &l, nil
	}
	return nil, errors.New("no live lease has this name")
}

// ReleaseLease implements LeaseStore.
func (f *FakeLeases) ReleaseLease(_ context.Context, name, holder string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.leases[name]; ok && l.Holder == holder {
		delete(f.leases, name)
	}
	return nil
}

// Holder returns who holds the lease named name, or "".
func (f *FakeLeases) Holder(name string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	if l, ok := f.leases[name]; ok && l.ExpiresAt.After(time.Now()) {
		return l.Holder
	}
	return ""
}
