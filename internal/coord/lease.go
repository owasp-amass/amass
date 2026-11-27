// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package coord

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"os"
	"strconv"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
)

// LeaseStore is the Asset Database's leases (asset-db
// repository.LeaseStore): named work one holder at a time may do.
type LeaseStore interface {
	AcquireLease(ctx context.Context, name, holder string, ttl time.Duration,
		data json.RawMessage) (*dbt.Lease, bool, error)
	ReleaseLease(ctx context.Context, name, holder string) error
	FindLease(ctx context.Context, name string) (*dbt.Lease, error)
}

// Leases takes leases for this process, so the tools sharing a database do
// a piece of work once: read a document version, start a watch's due run,
// supervise a run, apply merges. A nil Leases, for a database that keeps
// none, gives every lease: one process has no one to share with.
type Leases struct {
	Store  LeaseStore
	Holder string
}

// processHolder names this process as a lease holder: its host, its process
// and a random part, so two processes on one host differ.
var processHolder = func() string {
	b := make([]byte, 4)
	_, _ = rand.Read(b)
	return Actor() + "/" + strconv.Itoa(os.Getpid()) + "/" + hex.EncodeToString(b)
}()

// OpenLeases is the leases of v, a repository, or nil when it keeps none
// (asset-db keeps them in PostgreSQL and SQLite).
func OpenLeases(v any) *Leases {
	if s, ok := v.(LeaseStore); ok && s != nil {
		return &Leases{Store: s, Holder: processHolder}
	}
	return nil
}

// Try takes the lease named name for ttl and reports whether this process
// holds it; it is not renewed.
func (l *Leases) Try(name string, ttl time.Duration) bool {
	return l.TryData(name, ttl, nil)
}

// TryData is Try with data kept on the lease, marshaled as JSON, for others
// to read with Find; taking the lease again replaces it.
func (l *Leases) TryData(name string, ttl time.Duration, data any) bool {
	if l == nil || l.Store == nil {
		return true
	}
	var raw json.RawMessage
	if data != nil {
		var err error
		if raw, err = json.Marshal(data); err != nil {
			return false
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_, ok, err := l.Store.AcquireLease(ctx, name, l.Holder, ttl, raw)
	return err == nil && ok
}

// Find returns the lease named name while it has not expired.
func (l *Leases) Find(name string) (*dbt.Lease, bool) {
	if l == nil || l.Store == nil {
		return nil, false
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	lease, err := l.Store.FindLease(ctx, name)
	return lease, err == nil && lease != nil
}

// Release frees a lease this process holds.
func (l *Leases) Release(name string) {
	if l == nil || l.Store == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	_ = l.Store.ReleaseLease(ctx, name, l.Holder)
}

// Hold takes the lease named name and keeps renewing it, every third of
// ttl, until ctx ends or release is called, which frees it. It reports
// false, with a release that does nothing, when another holder has it. A
// lease whose holder stops renewing it (it exited) expires after ttl.
func (l *Leases) Hold(ctx context.Context, name string, ttl time.Duration) (release func(), ok bool) {
	if l == nil || l.Store == nil {
		return func() {}, true
	}
	if !l.Try(name, ttl) {
		return func() {}, false
	}

	hctx, stop := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		t := time.NewTicker(ttl / 3)
		defer t.Stop()
		for {
			select {
			case <-hctx.Done():
				return
			case <-t.C:
				l.Try(name, ttl)
			}
		}
	}()

	return func() {
		stop()
		<-done
		l.Release(name)
	}, true
}
