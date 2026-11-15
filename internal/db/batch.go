// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"slices"

	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
)

// maxEntitiesByIds is the most IDs asset-db's FindEntitiesByIds reads at once.
const maxEntitiesByIds = 1000

// EntitiesByIds returns the entities with the given IDs, by ID: in batches
// with asset-db's FindEntitiesByIds when the repository has it, otherwise
// one at a time. An ID with no entity, or that fails to read, is absent.
func EntitiesByIds(ctx context.Context, db repository.Repository, ids []string) map[string]*dbt.Entity {
	out := make(map[string]*dbt.Entity, len(ids))
	if batch, ok := db.(interface {
		FindEntitiesByIds(context.Context, []string) ([]*dbt.Entity, error)
	}); ok {
		for chunk := range slices.Chunk(ids, maxEntitiesByIds) {
			ents, err := batch.FindEntitiesByIds(ctx, chunk)
			if err != nil {
				break // read the rest one at a time
			}
			for _, e := range ents {
				out[e.ID] = e
			}
		}
	}
	for _, id := range ids {
		if _, done := out[id]; done {
			continue
		}
		if e, err := db.FindEntityById(ctx, id); err == nil && e != nil {
			out[id] = e
		}
	}

	return out
}

// edgeEnds returns the far ends of edges: their destinations, or their
// sources when in is true.
func edgeEnds(edges []*dbt.Edge, in bool) []string {
	ids := make([]string, 0, len(edges))
	for _, e := range edges {
		if in {
			ids = append(ids, e.FromEntity.ID)
		} else {
			ids = append(ids, e.ToEntity.ID)
		}
	}

	return ids
}

// EdgeEnds reads the entities at the far ends of edges, by ID: their
// destinations, or their sources when in is true.
func EdgeEnds(ctx context.Context, db repository.Repository, edges []*dbt.Edge, in bool) map[string]*dbt.Entity {
	return EntitiesByIds(ctx, db, edgeEnds(edges, in))
}
