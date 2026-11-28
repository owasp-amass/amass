// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package hubs

import (
	"context"
	"encoding/json"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

const (
	// Topic is the journal topic the thresholds are shared through, so
	// engines and tools on one database compute each once.
	Topic = "hubs"
	// retryAfter is how soon a threshold that could not be computed is
	// tried again.
	retryAfter = 10 * time.Minute
	// computeLease bounds the lease of the process computing a threshold.
	computeLease = 15 * time.Minute
	// thresholdKind is the kind of the topic's records.
	thresholdKind = "threshold"
)

// refreshEvery is how long a threshold is used before it is computed again.
func refreshEvery() time.Duration {
	return time.Duration(semantics.HubsCatalog().RefreshHours) * time.Hour
}

// Table keeps the thresholds of one database.
type Table struct {
	degrees repository.DegreeReader
	values  repository.ValueHistogramReader
	topic   *coord.Topic
	leases  *coord.Leases

	mu    sync.Mutex
	known map[string]Threshold
}

// tables holds each database's table, by repository.
var tables sync.Map

// For returns the table of repo's thresholds. A database that cannot count
// holders (Neo4j) has a table that always gives the caller's limit.
func For(repo repository.Repository) *Table {
	if repo == nil {
		return nil
	}
	if t, ok := tables.Load(repo); ok {
		return t.(*Table)
	}

	d, _ := repo.(repository.DegreeReader)
	v, _ := repo.(repository.ValueHistogramReader)
	t, _ := tables.LoadOrStore(repo, &Table{degrees: d, values: v, topic: coord.Open(repo, Topic),
		leases: coord.OpenLeases(repo), known: map[string]Threshold{}})
	return t.(*Table)
}

// Limit returns the most holders a value of the source may have before it
// is a hub, or fallback when the database cannot say.
func (t *Table) Limit(ctx context.Context, src Source, fallback int) int {
	n, _ := t.Threshold(ctx, src).For(fallback)
	return n
}

// Threshold returns the source's threshold: the one this process or another
// on the database computed within the refresh period (hubs.json), or a new one.
func (t *Table) Threshold(ctx context.Context, src Source) Threshold {
	if t == nil || !t.counts(src) {
		return Threshold{}
	}
	key := src.Key()

	// one computation at a time; a lens asks for a handful of sources
	t.mu.Lock()
	defer t.mu.Unlock()
	if th, ok := t.known[key]; ok && time.Since(th.At) < refreshEvery() {
		return th
	}

	th := t.compute(ctx, key, src)
	t.known[key] = th
	return th
}

// counts reports whether the database can count the source's holders.
func (t *Table) counts(src Source) bool {
	if src.Label != "" {
		return t.degrees != nil
	}
	return t.values != nil && src.AssetType != "" && src.Property != ""
}

// histogram reads the source's histogram from the database.
func (t *Table) histogram(ctx context.Context, src Source) (dbt.DegreeHistogram, error) {
	switch {
	case src.Label != "" && src.Value != "":
		return t.degrees.DegreeHistogramWhere(ctx, src.Direction, src.Label, oam.AssetType(src.AssetType),
			src.Property, src.Value)
	case src.Label != "":
		label := strings.ToLower(strings.TrimSpace(src.Label))
		hs, err := t.degrees.DegreeHistograms(ctx, src.Direction, []string{label})
		return hs[label], err
	case src.Attribute:
		return t.values.AttributeValueHistogram(ctx, oam.AssetType(src.AssetType), src.Property)
	default:
		return t.values.TagValueHistogram(ctx, oam.AssetType(src.AssetType), src.Property, src.Prefixes)
	}
}

// compute takes another process's recent threshold from the journal, or
// computes and records one, holding the key's lease meanwhile. Without the
// lease, or on a failed read, it uses the newest threshold known, and tries
// again after retryAfter.
func (t *Table) compute(ctx context.Context, key string, src Source) Threshold {
	recorded, ok := t.recorded(key)
	if ok && time.Since(recorded.At) < refreshEvery() {
		return recorded
	}
	retry := func() Threshold {
		recorded.At = time.Now().Add(retryAfter - refreshEvery())
		return recorded
	}

	lease := "hubs:" + key
	if !t.leases.Try(lease, computeLease) {
		return retry()
	}
	defer t.leases.Release(lease)

	h, err := t.histogram(ctx, src)
	if err != nil {
		return retry()
	}
	th := Derive(key, h)
	if t.topic != nil {
		_, _ = t.topic.Append(thresholdKind, key, th)
	}
	return th
}

// recorded returns the newest threshold recorded for key.
func (t *Table) recorded(key string) (Threshold, bool) {
	if t.topic == nil {
		return Threshold{}, false
	}
	recs, err := t.topic.ReadWhere(dbt.JournalFilter{Key: key, Kinds: []string{thresholdKind}}, 0)
	if err != nil || len(recs) == 0 {
		return Threshold{}, false
	}
	var th Threshold
	if json.Unmarshal(recs[len(recs)-1].Data, &th) != nil {
		return Threshold{}, false
	}
	return th, true
}
