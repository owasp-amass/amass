// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"log/slog"
	"os"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// DBStatsEnv turns on counting a session's database calls by the plugin
// that made them, logged when the session ends, to find the lookups worth
// batching.
const DBStatsEnv = "AMASS_DB_STATS"

// dbStatsTop is how many callers the session log lists.
const dbStatsTop = 40

// dbStats counts database calls and their time by caller and method.
type dbStats struct {
	mu    sync.Mutex
	calls map[string]*dbCallStat
}

type dbCallStat struct {
	n    int
	took time.Duration
}

// countingRepository counts the calls made through a session's repository.
// It also offers the optional reads the SQL repositories have, so code that
// looks for them finds them; it wraps only repositories that have them.
type countingRepository struct {
	repository.Repository
	stats *dbStats
}

// sqlReads are the optional reads countingRepository forwards.
type sqlReads interface {
	ReadEdgesLimited(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, bool, error)
	ReadEdgesPage(context.Context, *dbt.Entity, string, time.Time, *dbt.EdgeCursor, int, ...string) ([]*dbt.Edge,
		*dbt.EdgeCursor, error)
	FindEntitiesByIds(context.Context, []string) ([]*dbt.Entity, error)
	ReadEdgesPerLabel(context.Context, *dbt.Entity, string, time.Time, int, ...string) ([]*dbt.Edge, []string, error)
	ReadEdgesForEntities(context.Context, []string, string, time.Time, int, ...string) (map[string][]*dbt.Edge,
		[]string, error)
	ReplaceAsset(context.Context, oam.Asset) (*dbt.Entity, error)
	FindEntitiesByTagValue(context.Context, oam.AssetType, string, string, bool, time.Time, int) ([]*dbt.Entity,
		bool, error)
	FindEntitiesByAttribute(context.Context, oam.AssetType, string, string, bool, time.Time, int) ([]*dbt.Entity,
		bool, error)
}

// withDBStats wraps repo to count its calls when DBStatsEnv is set and repo
// has every optional read; otherwise it returns repo unchanged.
func withDBStats(repo repository.Repository) (repository.Repository, *dbStats) {
	if v := os.Getenv(DBStatsEnv); v == "" || v == "0" || strings.EqualFold(v, "false") {
		return repo, nil
	}
	if _, ok := repo.(sqlReads); !ok {
		return repo, nil
	}

	stats := &dbStats{calls: map[string]*dbCallStat{}}
	return &countingRepository{Repository: repo, stats: stats}, stats
}

// record notes one call of method by the plugin function that made it.
func (s *dbStats) record(method string, start time.Time) {
	d := time.Since(start)
	key := caller() + " " + method

	s.mu.Lock()
	defer s.mu.Unlock()
	c := s.calls[key]
	if c == nil {
		c = &dbCallStat{}
		s.calls[key] = c
	}

	c.n++
	c.took += d
}

// caller names the first function on the stack under engine/plugins, or
// the first outside this file and asset-db.
func caller() string {
	pcs := make([]uintptr, 24)
	n := runtime.Callers(4, pcs)
	frames := runtime.CallersFrames(pcs[:n])

	var first string
	for {
		f, more := frames.Next()
		if i := strings.Index(f.Function, "/engine/plugins/"); i >= 0 {
			return f.Function[i+len("/engine/plugins/"):]
		}
		if first == "" && !strings.Contains(f.Function, "/asset-db/") {
			if i := strings.LastIndex(f.Function, "/"); i >= 0 {
				first = f.Function[i+1:]
			} else {
				first = f.Function
			}
		}
		if !more {
			break
		}
	}
	if first == "" {
		return "unknown"
	}

	return first
}

// log writes the callers that spent the most time in the database.
func (s *dbStats) log(l *slog.Logger) {
	if s == nil || l == nil {
		return
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	type row struct {
		key string
		c   dbCallStat
	}
	rows := make([]row, 0, len(s.calls))
	var calls int
	var took time.Duration
	for k, c := range s.calls {
		rows = append(rows, row{key: k, c: *c})
		calls += c.n
		took += c.took
	}

	sort.Slice(rows, func(i, j int) bool { return rows[i].c.took > rows[j].c.took })

	l.Info("database calls", "calls", calls, "took", took.Round(time.Millisecond).String())
	for i, r := range rows {
		if i >= dbStatsTop {
			break
		}

		l.Info("database calls by caller", "caller", r.key, "calls", r.c.n,
			"took", r.c.took.Round(time.Millisecond).String(),
			"mean", (r.c.took / time.Duration(r.c.n)).Round(time.Microsecond).String())
	}
}

func (r *countingRepository) sql() sqlReads { return r.Repository.(sqlReads) }

func (r *countingRepository) CreateEntity(ctx context.Context, e *dbt.Entity) (*dbt.Entity, error) {
	defer r.stats.record("CreateEntity", time.Now())
	return r.Repository.CreateEntity(ctx, e)
}

func (r *countingRepository) CreateAsset(ctx context.Context, a oam.Asset) (*dbt.Entity, error) {
	defer r.stats.record("CreateAsset", time.Now())
	return r.Repository.CreateAsset(ctx, a)
}

func (r *countingRepository) FindEntityById(ctx context.Context, id string) (*dbt.Entity, error) {
	defer r.stats.record("FindEntityById", time.Now())
	return r.Repository.FindEntityById(ctx, id)
}

func (r *countingRepository) FindEntitiesByContent(ctx context.Context, t oam.AssetType, since time.Time, limit int,
	f dbt.ContentFilters) ([]*dbt.Entity, error) {
	defer r.stats.record("FindEntitiesByContent", time.Now())
	return r.Repository.FindEntitiesByContent(ctx, t, since, limit, f)
}

func (r *countingRepository) FindEntitiesByType(ctx context.Context, t oam.AssetType, since time.Time,
	limit int) ([]*dbt.Entity, error) {
	defer r.stats.record("FindEntitiesByType", time.Now())
	return r.Repository.FindEntitiesByType(ctx, t, since, limit)
}

func (r *countingRepository) DeleteEntity(ctx context.Context, id string) error {
	defer r.stats.record("DeleteEntity", time.Now())
	return r.Repository.DeleteEntity(ctx, id)
}

func (r *countingRepository) CreateEdge(ctx context.Context, e *dbt.Edge) (*dbt.Edge, error) {
	defer r.stats.record("CreateEdge", time.Now())
	return r.Repository.CreateEdge(ctx, e)
}

func (r *countingRepository) FindEdgeById(ctx context.Context, id string) (*dbt.Edge, error) {
	defer r.stats.record("FindEdgeById", time.Now())
	return r.Repository.FindEdgeById(ctx, id)
}

func (r *countingRepository) IncomingEdges(ctx context.Context, e *dbt.Entity, since time.Time,
	labels ...string) ([]*dbt.Edge, error) {
	defer r.stats.record("IncomingEdges", time.Now())
	return r.Repository.IncomingEdges(ctx, e, since, labels...)
}

func (r *countingRepository) OutgoingEdges(ctx context.Context, e *dbt.Entity, since time.Time,
	labels ...string) ([]*dbt.Edge, error) {
	defer r.stats.record("OutgoingEdges", time.Now())
	return r.Repository.OutgoingEdges(ctx, e, since, labels...)
}

func (r *countingRepository) DeleteEdge(ctx context.Context, id string) error {
	defer r.stats.record("DeleteEdge", time.Now())
	return r.Repository.DeleteEdge(ctx, id)
}

func (r *countingRepository) CreateEntityTag(ctx context.Context, e *dbt.Entity,
	t *dbt.EntityTag) (*dbt.EntityTag, error) {
	defer r.stats.record("CreateEntityTag", time.Now())
	return r.Repository.CreateEntityTag(ctx, e, t)
}

func (r *countingRepository) CreateEntityProperty(ctx context.Context, e *dbt.Entity,
	p oam.Property) (*dbt.EntityTag, error) {
	defer r.stats.record("CreateEntityProperty", time.Now())
	return r.Repository.CreateEntityProperty(ctx, e, p)
}

func (r *countingRepository) FindEntityTagById(ctx context.Context, id string) (*dbt.EntityTag, error) {
	defer r.stats.record("FindEntityTagById", time.Now())
	return r.Repository.FindEntityTagById(ctx, id)
}

func (r *countingRepository) FindEntityTags(ctx context.Context, e *dbt.Entity, since time.Time,
	names ...string) ([]*dbt.EntityTag, error) {
	defer r.stats.record("FindEntityTags", time.Now())
	return r.Repository.FindEntityTags(ctx, e, since, names...)
}

func (r *countingRepository) DeleteEntityTag(ctx context.Context, id string) error {
	defer r.stats.record("DeleteEntityTag", time.Now())
	return r.Repository.DeleteEntityTag(ctx, id)
}

func (r *countingRepository) CreateEdgeTag(ctx context.Context, e *dbt.Edge, t *dbt.EdgeTag) (*dbt.EdgeTag, error) {
	defer r.stats.record("CreateEdgeTag", time.Now())
	return r.Repository.CreateEdgeTag(ctx, e, t)
}

func (r *countingRepository) CreateEdgeProperty(ctx context.Context, e *dbt.Edge,
	p oam.Property) (*dbt.EdgeTag, error) {
	defer r.stats.record("CreateEdgeProperty", time.Now())
	return r.Repository.CreateEdgeProperty(ctx, e, p)
}

func (r *countingRepository) FindEdgeTagById(ctx context.Context, id string) (*dbt.EdgeTag, error) {
	defer r.stats.record("FindEdgeTagById", time.Now())
	return r.Repository.FindEdgeTagById(ctx, id)
}

func (r *countingRepository) FindEdgeTags(ctx context.Context, e *dbt.Edge, since time.Time,
	names ...string) ([]*dbt.EdgeTag, error) {
	defer r.stats.record("FindEdgeTags", time.Now())
	return r.Repository.FindEdgeTags(ctx, e, since, names...)
}

func (r *countingRepository) DeleteEdgeTag(ctx context.Context, id string) error {
	defer r.stats.record("DeleteEdgeTag", time.Now())
	return r.Repository.DeleteEdgeTag(ctx, id)
}

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
