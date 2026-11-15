// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// batchAssets keeps the assets a search read in one batch, so the far ends
// of an edge list cost one read instead of one each. Its zero value is
// ready; on a graph that cannot batch it reads nothing.
type batchAssets struct {
	read map[string]graph.Asset
}

// load reads the far ends of edges (the destination of "out" edges, the
// source of "in" edges) not yet read, in one batch that spend pays for.
func (b *batchAssets) load(ctx context.Context, g graph.Graph, edges []graph.Relation, dir string, spend func() bool) error {
	if _, ok := g.(graph.AssetBatchReader); !ok {
		return nil
	}
	var ids []string
	want := map[string]bool{}
	for _, e := range edges {
		id := e.ToID
		if dir == "in" {
			id = e.FromID
		}
		if _, done := b.read[id]; !done && id != "" && !want[id] {
			want[id] = true
			ids = append(ids, id)
		}
	}
	return b.loadIDs(ctx, g, ids, spend)
}

// loadIDs reads the assets ids not yet read in one batch that spend pays
// for.
func (b *batchAssets) loadIDs(ctx context.Context, g graph.Graph, ids []string, spend func() bool) error {
	var need []string
	for _, id := range ids {
		if _, done := b.read[id]; !done {
			need = append(need, id)
		}
	}
	if len(need) < 2 || !spend() {
		return nil
	}
	read, err := graph.AssetsByID(ctx, g, need)
	if err != nil {
		return err
	}
	if b.read == nil {
		b.read = make(map[string]graph.Asset, len(read))
	}
	for id, a := range read {
		b.read[id] = a
	}
	return nil
}

// get returns an asset a batch read.
func (b *batchAssets) get(id string) (graph.Asset, bool) {
	a, ok := b.read[id]
	return a, ok
}
