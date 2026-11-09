// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	neo4jdb "github.com/neo4j/neo4j-go-driver/v5/neo4j"
	"github.com/owasp-amass/amass/v5/config"
	neo4jrepo "github.com/owasp-amass/asset-db/repository/neo4j"
	dbt "github.com/owasp-amass/asset-db/types"
)

// neo4jEdgeTimeout matches the per-query timeout used by asset-db's Neo4j
// repository methods.
const neo4jEdgeTimeout = 30 * time.Second

// Neo4jDatabaseName returns the Neo4j database name for the primary graph
// database in cfg, or "" when the primary store is not Neo4j or the DSN
// names no database (the server default is then used). asset-db derives the
// name the same way: the path of the bolt DSN.
func Neo4jDatabaseName(cfg *config.Config) string {
	if cfg == nil {
		return ""
	}
	for _, db := range cfg.GraphDBs {
		if db == nil || !db.Primary || !strings.EqualFold(db.System, "bolt") {
			continue
		}

		u, err := url.Parse(db.URL)
		if err != nil {
			return ""
		}

		return strings.TrimPrefix(u.Path, "/")
	}

	return ""
}

// neo4jBoundedEdgeQuery builds a Cypher query that returns at most limit+1
// relationship element IDs touching one entity, newest first. Labels are
// matched against the relationship type, which asset-db stores upper-cased.
func neo4jBoundedEdgeQuery(entityID, direction string, since time.Time, limit int, labels []string) (string, map[string]any, error) {
	if entityID == "" {
		return "", nil, errors.New("missing entity ID")
	}
	if limit < 1 || limit > 500 {
		return "", nil, errors.New("edge limit must be 1..500")
	}

	var pattern string
	switch direction {
	case "in":
		pattern = "(n:Entity {entity_id: $eid})<-[r]-(:Entity)"
	case "out":
		pattern = "(n:Entity {entity_id: $eid})-[r]->(:Entity)"
	case "both":
		pattern = "(n:Entity {entity_id: $eid})-[r]-(:Entity)"
	default:
		return "", nil, errors.New("invalid edge direction")
	}
	if len(labels) > 8 {
		return "", nil, errors.New("too many edge labels")
	}

	params := map[string]any{"eid": entityID, "lim": int64(limit + 1)}
	var where []string
	if !since.IsZero() {
		t := since.UTC()
		t = time.Date(t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second(), t.Nanosecond(), time.UTC)
		params["since"] = neo4jdb.LocalDateTime(t)
		where = append(where, "r.updated_at >= $since")
	}
	if len(labels) > 0 {
		types := make([]string, 0, len(labels))
		for _, l := range labels {
			if l == "" || len(l) > 128 {
				return "", nil, errors.New("invalid edge label")
			}

			types = append(types, strings.ToUpper(l))
		}

		params["types"] = types
		where = append(where, "type(r) IN $types")
	}

	query := "MATCH " + pattern
	if len(where) > 0 {
		query += " WHERE " + strings.Join(where, " AND ")
	}

	query += " RETURN DISTINCT elementId(r) AS rid, r.updated_at AS updated ORDER BY updated DESC, rid DESC LIMIT $lim"
	return query, params, nil
}

// neo4jEdgesLimited bounds the neighbourhood read on the Neo4j server with
// LIMIT, then hydrates each returned relationship through asset-db's public
// FindEdgeById so relation decoding stays in asset-db. It needs no asset-db
// changes; a native ReadEdgesLimited, if one is added later, takes priority.
func neo4jEdgesLimited(ctx context.Context, repo *neo4jrepo.NeoRepository, database string, entity *dbt.Entity, direction string, since time.Time, limit int, labels ...string) ([]*dbt.Edge, bool, error) {
	if repo == nil || repo.DB == nil || entity == nil {
		return nil, false, errors.New("missing Neo4j repository or entity")
	}

	query, params, err := neo4jBoundedEdgeQuery(entity.ID, direction, since, limit, labels)
	if err != nil {
		return nil, false, err
	}

	tctx, cancel := context.WithTimeout(ctx, neo4jEdgeTimeout)
	defer cancel()
	opts := []neo4jdb.ExecuteQueryConfigurationOption{}
	if database != "" {
		opts = append(opts, neo4jdb.ExecuteQueryWithDatabase(database))
	}

	result, err := neo4jdb.ExecuteQuery(tctx, repo.DB, query, params, neo4jdb.EagerResultTransformer, opts...)
	if err != nil {
		return nil, false, fmt.Errorf("bounded Neo4j edge query: %w", err)
	}

	more := len(result.Records) > limit
	out := make([]*dbt.Edge, 0, min(len(result.Records), limit))
	for _, record := range result.Records {
		if len(out) >= limit {
			break
		}

		rid, isnil, err := neo4jdb.GetRecordValue[string](record, "rid")
		if err != nil || isnil || rid == "" {
			return nil, false, errors.New("malformed Neo4j relationship ID")
		}

		edge, err := repo.FindEdgeById(tctx, rid)
		if err != nil {
			return nil, false, fmt.Errorf("hydrate Neo4j edge %s: %w", rid, err)
		}

		out = append(out, edge)
	}

	return out, more, nil
}
