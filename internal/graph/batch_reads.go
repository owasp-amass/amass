// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import "context"

// FarAssets reads, in one batch when g is an AssetBatchReader, the assets at
// the far end of edges from the asset id that have reports it lacks (nil
// for none). It returns the assets found, or nil when g cannot batch or
// fewer than two are needed; read the rest with AssetFrom.
func FarAssets(ctx context.Context, g Graph, id string, edges []Relation, have func(string) bool) (map[string]Asset, error) {
	if _, ok := g.(AssetBatchReader); !ok {
		return nil, nil
	}
	var ids []string
	want := map[string]bool{}
	for _, e := range edges {
		other := e.ToID
		if e.ToID == id {
			other = e.FromID
		}
		if other == "" || other == id || want[other] || (have != nil && have(other)) {
			continue
		}
		want[other] = true
		ids = append(ids, other)
	}
	return AssetsByID(ctx, g, ids)
}

// AssetsByID reads the assets ids in one batch when g is an
// AssetBatchReader; otherwise, or for fewer than two, it returns nil. Read
// the rest with AssetFrom.
func AssetsByID(ctx context.Context, g Graph, ids []string) (map[string]Asset, error) {
	batch, ok := g.(AssetBatchReader)
	if !ok || len(ids) < 2 {
		return nil, nil
	}
	return batch.GetAssets(ctx, ids)
}

// AssetFrom returns the asset id from read, the result of FarAssets, or
// reads it from g when it is not there.
func AssetFrom(ctx context.Context, g Graph, read map[string]Asset, id string) (Asset, error) {
	if a, ok := read[id]; ok {
		return a, nil
	}
	return g.GetAsset(ctx, id)
}
