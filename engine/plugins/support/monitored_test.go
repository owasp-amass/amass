// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// tagRepo stores last_monitored tags in memory and counts the reads.
type tagRepo struct {
	repository.Repository
	mu    sync.Mutex
	reads int
	tags  map[string][]*dbt.EntityTag
}

func (r *tagRepo) FindEntityTags(_ context.Context, e *dbt.Entity, since time.Time,
	names ...string) ([]*dbt.EntityTag, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	r.reads++
	var out []*dbt.EntityTag
	for _, t := range r.tags[e.ID] {
		if !t.LastSeen.Before(since) {
			out = append(out, t)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no tags found for entity")
	}

	return out, nil
}

func (r *tagRepo) CreateEntityProperty(_ context.Context, e *dbt.Entity, p oam.Property) (*dbt.EntityTag, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	now := monitoredNow()
	for _, t := range r.tags[e.ID] {
		if t.Property.Value() == p.Value() {
			t.LastSeen = now
			return t, nil
		}
	}

	t := &dbt.EntityTag{ID: "t", Entity: e, Property: p, CreatedAt: now, LastSeen: now}
	r.tags[e.ID] = append(r.tags[e.ID], t)
	return t, nil
}

type tagSession struct {
	et.Session
	id   uuid.UUID
	repo *tagRepo
}

func (s *tagSession) ID() uuid.UUID { return s.id }

func (s *tagSession) Ctx() context.Context { return context.Background() }

func (s *tagSession) DB() repository.Repository { return s.repo }

func TestAssetMonitoredSharesOneRead(t *testing.T) {
	now := time.Date(2026, 11, 15, 12, 0, 0, 0, time.UTC)
	defer func(f func() time.Time) { monitoredNow = f }(monitoredNow)
	monitoredNow = func() time.Time { return now }

	mark := func(source string, at time.Time) *dbt.EntityTag {
		return &dbt.EntityTag{Property: oamgen.SimpleProperty{PropertyName: "last_monitored", PropertyValue: source},
			LastSeen: at}
	}

	repo := &tagRepo{tags: map[string][]*dbt.EntityTag{}}
	sess := &tagSession{id: uuid.New(), repo: repo}
	asset := &dbt.Entity{ID: "1", Asset: &oamdns.FQDN{Name: "www.example.com"}}
	repo.tags["1"] = []*dbt.EntityTag{mark("DNS", now.Add(-time.Hour)), mark("WHOIS", now.Add(-time.Hour)),
		mark("HTTP-Probes", now.Add(-3*time.Hour))}

	// A revisited asset: the first check reads the marks, and the other
	// plugins that marked it within their TTL are answered from that read.
	dns, whois, http := &et.Source{Name: "DNS"}, &et.Source{Name: "WHOIS"}, &et.Source{Name: "HTTP-Probes"}
	if !AssetMonitoredWithinTTL(sess, asset, dns, now.Add(-2*time.Hour)) ||
		!AssetMonitoredWithinTTL(sess, asset, whois, now.Add(-2*time.Hour)) || repo.reads != 1 {
		t.Errorf("plugins within their TTL were not answered from one read (reads %d)", repo.reads)
	}

	// A no always comes from a fresh read, so a plugin queries its data
	// source only after the same check as before.
	if AssetMonitoredWithinTTL(sess, asset, http, now.Add(-2*time.Hour)) || repo.reads != 2 {
		t.Errorf("a mark older than the TTL counted, or was not read again (reads %d)", repo.reads)
	}

	repo.tags["1"] = append(repo.tags["1"], mark("Lookalike-Domains", now))
	if !AssetMonitoredWithinTTL(sess, asset, &et.Source{Name: "Lookalike-Domains"}, now.Add(-time.Hour)) {
		t.Error("a mark made since the cached read was missed")
	}

	// A mark this session makes is answered from the cache.
	reads := repo.reads
	MarkAssetMonitored(sess, asset, http)
	if !AssetMonitoredWithinTTL(sess, asset, http, now.Add(-time.Minute)) || repo.reads != reads {
		t.Errorf("a new mark was not seen from the cache (reads %d, before %d)", repo.reads, reads)
	}

	// Another session (perhaps another database) reads for itself.
	other := &tagSession{id: uuid.New(), repo: repo}
	_ = AssetMonitoredWithinTTL(other, asset, dns, now.Add(-2*time.Hour))
	if repo.reads != reads+1 {
		t.Errorf("another session shared the cache (reads %d)", repo.reads)
	}

	// After monitoredFor, the marks are read again.
	now = now.Add(monitoredFor + time.Second)
	_ = AssetMonitoredWithinTTL(sess, asset, dns, now.Add(-2*time.Hour))
	if repo.reads != reads+2 {
		t.Errorf("an expired entry was not read again (reads %d)", repo.reads)
	}
}

func TestMonitoredCacheIsBounded(t *testing.T) {
	defer func() { monitored.entries = map[monitoredKey]*monitoredEntry{} }()

	id := uuid.New()
	for i := range maxMonitoredEntries + 10 {
		monitoredStore(monitoredKey{session: id, entity: string(rune(i))}, map[string]time.Time{})
	}
	if n := len(monitored.entries); n > maxMonitoredEntries {
		t.Errorf("the cache holds %d entries, more than %d", n, maxMonitoredEntries)
	}
}
