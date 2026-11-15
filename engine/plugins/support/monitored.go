// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// monitoredFor is how long one read of an asset's last_monitored tags can
// tell the other plugins handling it that they already monitored it. Only
// that answer comes from the cache, which can only make a plugin skip work:
// a plugin is told it has not monitored an asset only after a fresh read,
// as before, so sharing the read never sends a data source a query it would
// not otherwise get. A mark's time only moves forward, so a cached mark
// within a plugin's TTL is still within it; the window bounds memory.
const monitoredFor = time.Minute

// maxMonitoredEntries bounds the cache; it is emptied when full.
const maxMonitoredEntries = 1 << 16

type monitoredKey struct {
	session uuid.UUID
	entity  string
}

type monitoredEntry struct {
	read time.Time
	// last is when each source last marked the asset monitored.
	last map[string]time.Time
}

// monitored caches each asset's last_monitored tags for a short time, per
// session: sessions can use different databases.
var monitored = struct {
	sync.Mutex
	entries map[monitoredKey]*monitoredEntry
}{entries: map[monitoredKey]*monitoredEntry{}}

// monitoredNow is the clock the cache uses; tests replace it.
var monitoredNow = time.Now

func monitoredLookup(k monitoredKey) (*monitoredEntry, bool) {
	monitored.Lock()
	defer monitored.Unlock()

	e, ok := monitored.entries[k]
	if !ok || monitoredNow().Sub(e.read) > monitoredFor {
		return nil, false
	}

	return e, true
}

func monitoredStore(k monitoredKey, last map[string]time.Time) {
	monitored.Lock()
	defer monitored.Unlock()

	now := monitoredNow()
	if len(monitored.entries) >= maxMonitoredEntries {
		for key, e := range monitored.entries {
			if now.Sub(e.read) > monitoredFor {
				delete(monitored.entries, key)
			}
		}
		if len(monitored.entries) >= maxMonitoredEntries {
			monitored.entries = map[monitoredKey]*monitoredEntry{}
		}
	}

	monitored.entries[k] = &monitoredEntry{read: now, last: last}
}

// monitoredMark records a mark in a cached entry, when there is one.
func monitoredMark(k monitoredKey, source string, at time.Time) {
	monitored.Lock()
	defer monitored.Unlock()

	if e, ok := monitored.entries[k]; ok {
		e.last[source] = at
	}
}

// cachedMonitored returns when src last marked the asset, from a recent
// read made for any plugin of the session.
func cachedMonitored(k monitoredKey, source string) (time.Time, bool) {
	e, ok := monitoredLookup(k)
	if !ok {
		return time.Time{}, false
	}

	monitored.Lock()
	defer monitored.Unlock()

	t, ok := e.last[source]
	return t, ok
}

// readMonitored reads when each source last marked the asset monitored and
// caches it for the other plugins handling the asset.
func readMonitored(session et.Session, k monitoredKey, asset *dbt.Entity) map[string]time.Time {
	ctx, cancel := context.WithTimeout(session.Ctx(), 3*time.Second)
	defer cancel()

	last := map[string]time.Time{}
	tags, err := session.DB().FindEntityTags(ctx, asset, time.Time{}, "last_monitored")
	for _, tag := range tags {
		if t, ok := last[tag.Property.Value()]; !ok || tag.LastSeen.After(t) {
			last[tag.Property.Value()] = tag.LastSeen
		}
	}
	if err == nil {
		cp := make(map[string]time.Time, len(last))
		for s, t := range last {
			cp[s] = t
		}

		monitoredStore(k, cp)
	}

	return last
}

func MarkAssetMonitored(session et.Session, asset *dbt.Entity, src *et.Source) {
	if asset == nil || src == nil {
		return
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 3*time.Second)
	defer cancel()

	tag, err := session.DB().CreateEntityProperty(ctx, asset, oamgen.SimpleProperty{
		PropertyName:  "last_monitored",
		PropertyValue: src.Name,
	})
	if err != nil {
		return
	}

	at := monitoredNow()
	if tag != nil && !tag.LastSeen.IsZero() {
		at = tag.LastSeen
	}

	monitoredMark(monitoredKey{session: session.ID(), entity: asset.ID}, src.Name, at)
}

// AssetMonitoredWithinTTL reports whether src marked the asset monitored
// since the given time. A recent read for another plugin can answer yes; a
// no always comes from a fresh read.
func AssetMonitoredWithinTTL(session et.Session, asset *dbt.Entity, src *et.Source, since time.Time) bool {
	if asset == nil || src == nil || since.IsZero() {
		return false
	}

	k := monitoredKey{session: session.ID(), entity: asset.ID}
	if t, ok := cachedMonitored(k, src.Name); ok && !t.Before(since) {
		return true
	}

	t, ok := readMonitored(session, k, asset)[src.Name]
	return ok && !t.Before(since)
}
