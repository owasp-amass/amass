// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"net/netip"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// The optional capabilities (sqlReads) countingRepository counts and passes
// to the repository it wraps.

func (r *countingRepository) sql() sqlReads { return r.Repository.(sqlReads) }

func (r *countingRepository) ReadEdgesLimited(ctx context.Context, e *dbt.Entity, dir string, since time.Time,
	limit int, labels ...string) ([]*dbt.Edge, bool, error) {
	defer r.stats.record("ReadEdgesLimited", time.Now())
	return r.sql().ReadEdgesLimited(ctx, e, dir, since, limit, labels...)
}

func (r *countingRepository) ReadEdgesPage(ctx context.Context, e *dbt.Entity, dir string, since time.Time,
	after *dbt.EdgeCursor, limit int, labels ...string) ([]*dbt.Edge, *dbt.EdgeCursor, error) {
	defer r.stats.record("ReadEdgesPage", time.Now())
	return r.sql().ReadEdgesPage(ctx, e, dir, since, after, limit, labels...)
}

func (r *countingRepository) FindEntitiesByIds(ctx context.Context, ids []string) ([]*dbt.Entity, error) {
	defer r.stats.record("FindEntitiesByIds", time.Now())
	return r.sql().FindEntitiesByIds(ctx, ids)
}

func (r *countingRepository) ReadEdgesPerLabel(ctx context.Context, e *dbt.Entity, dir string, since time.Time,
	perLabel int, labels ...string) ([]*dbt.Edge, []string, error) {
	defer r.stats.record("ReadEdgesPerLabel", time.Now())
	return r.sql().ReadEdgesPerLabel(ctx, e, dir, since, perLabel, labels...)
}

func (r *countingRepository) ReadEdgesForEntities(ctx context.Context, ids []string, dir string, since time.Time,
	perEntity int, labels ...string) (map[string][]*dbt.Edge, []string, error) {
	defer r.stats.record("ReadEdgesForEntities", time.Now())
	return r.sql().ReadEdgesForEntities(ctx, ids, dir, since, perEntity, labels...)
}

func (r *countingRepository) ReplaceAsset(ctx context.Context, a oam.Asset) (*dbt.Entity, error) {
	defer r.stats.record("ReplaceAsset", time.Now())
	return r.sql().ReplaceAsset(ctx, a)
}

func (r *countingRepository) FindEntitiesByTagValue(ctx context.Context, t oam.AssetType, name, value string,
	contains bool, since time.Time, limit int) ([]*dbt.Entity, bool, error) {
	defer r.stats.record("FindEntitiesByTagValue", time.Now())
	return r.sql().FindEntitiesByTagValue(ctx, t, name, value, contains, since, limit)
}

func (r *countingRepository) FindEntitiesByAttribute(ctx context.Context, t oam.AssetType, key, value string,
	contains bool, since time.Time, limit int) ([]*dbt.Entity, bool, error) {
	defer r.stats.record("FindEntitiesByAttribute", time.Now())
	return r.sql().FindEntitiesByAttribute(ctx, t, key, value, contains, since, limit)
}

func (r *countingRepository) FindEntitiesByTagValueAfter(ctx context.Context, t oam.AssetType, name, value string,
	contains bool, since time.Time, after string, limit int) ([]*dbt.Entity, bool, error) {
	defer r.stats.record("FindEntitiesByTagValue", time.Now())
	return r.sql().FindEntitiesByTagValueAfter(ctx, t, name, value, contains, since, after, limit)
}

func (r *countingRepository) FindEntitiesByAttributeAfter(ctx context.Context, t oam.AssetType, key, value string,
	contains bool, since time.Time, after string, limit int) ([]*dbt.Entity, bool, error) {
	defer r.stats.record("FindEntitiesByAttribute", time.Now())
	return r.sql().FindEntitiesByAttributeAfter(ctx, t, key, value, contains, since, after, limit)
}

func (r *countingRepository) ReadSteps(ctx context.Context, ids []string, steps []dbt.Step,
	since time.Time) ([]*dbt.Edge, error) {
	defer r.stats.record("ReadSteps", time.Now())
	return r.sql().ReadSteps(ctx, ids, steps, since)
}

func (r *countingRepository) GraphChanges(ctx context.Context, since time.Time) (*dbt.GraphChanges, error) {
	defer r.stats.record("GraphChanges", time.Now())
	return r.sql().GraphChanges(ctx, since)
}

func (r *countingRepository) CoKeyedGroups(ctx context.Context, atype oam.AssetType, key dbt.CoKey, param string,
	maxGroup int, since time.Time) ([]dbt.CoKeyGroup, error) {
	defer r.stats.record("CoKeyedGroups", time.Now())
	return r.sql().CoKeyedGroups(ctx, atype, key, param, maxGroup, since)
}

func (r *countingRepository) DegreeHistograms(ctx context.Context, direction string,
	labels []string) (map[string]dbt.DegreeHistogram, error) {
	defer r.stats.record("DegreeHistograms", time.Now())
	return r.sql().DegreeHistograms(ctx, direction, labels)
}

func (r *countingRepository) DegreeHistogramWhere(ctx context.Context, direction, label string, atype oam.AssetType,
	key, value string) (dbt.DegreeHistogram, error) {
	defer r.stats.record("DegreeHistogramWhere", time.Now())
	return r.sql().DegreeHistogramWhere(ctx, direction, label, atype, key, value)
}

func (r *countingRepository) EntitiesPage(ctx context.Context, atype oam.AssetType, since time.Time,
	after *dbt.EntityCursor, limit int) ([]*dbt.Entity, *dbt.EntityCursor, error) {
	defer r.stats.record("EntitiesPage", time.Now())
	return r.sql().EntitiesPage(ctx, atype, since, after, limit)
}

func (r *countingRepository) FindAddressesInRange(ctx context.Context, prefix netip.Prefix,
	limit int) ([]*dbt.Entity, bool, error) {
	defer r.stats.record("FindAddressesInRange", time.Now())
	return r.sql().FindAddressesInRange(ctx, prefix, limit)
}

func (r *countingRepository) FindNetblocksContaining(ctx context.Context, addr netip.Addr,
	limit int) ([]*dbt.Entity, error) {
	defer r.stats.record("FindNetblocksContaining", time.Now())
	return r.sql().FindNetblocksContaining(ctx, addr, limit)
}

func (r *countingRepository) TagValueHistogram(ctx context.Context, atype oam.AssetType, name string,
	prefixes []string) (dbt.DegreeHistogram, error) {
	defer r.stats.record("TagValueHistogram", time.Now())
	return r.sql().TagValueHistogram(ctx, atype, name, prefixes)
}

func (r *countingRepository) AttributeValueHistogram(ctx context.Context, atype oam.AssetType,
	key string) (dbt.DegreeHistogram, error) {
	defer r.stats.record("AttributeValueHistogram", time.Now())
	return r.sql().AttributeValueHistogram(ctx, atype, key)
}

func (r *countingRepository) StartRun(ctx context.Context, run *dbt.CollectionRun) (*dbt.CollectionRun, error) {
	defer r.stats.record("StartRun", time.Now())
	return r.sql().StartRun(ctx, run)
}

func (r *countingRepository) FinishRun(ctx context.Context, id, status string,
	finished time.Time) (*dbt.CollectionRun, error) {
	defer r.stats.record("FinishRun", time.Now())
	return r.sql().FinishRun(ctx, id, status, finished)
}

func (r *countingRepository) FindRunById(ctx context.Context, id string) (*dbt.CollectionRun, error) {
	defer r.stats.record("FindRunById", time.Now())
	return r.sql().FindRunById(ctx, id)
}

func (r *countingRepository) FindRuns(ctx context.Context, since time.Time, limit int,
	tools ...string) ([]*dbt.CollectionRun, error) {
	defer r.stats.record("FindRuns", time.Now())
	return r.sql().FindRuns(ctx, since, limit, tools...)
}
