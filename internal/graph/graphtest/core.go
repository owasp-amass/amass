// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graphtest

import (
	"context"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

type FakeGraph struct {
	Assets       map[string]graph.Asset
	Links        []graph.Relation
	EvidenceByID map[string][]graph.Evidence
}

func (g FakeGraph) GetAsset(_ context.Context, id string) (graph.Asset, error) {
	a, ok := g.Assets[id]
	if !ok {
		return graph.Asset{}, errors.New("missing asset")
	}

	return a, nil
}

func (g FakeGraph) FindAssets(_ context.Context, kind string, _ time.Time, limit int) ([]graph.Asset, error) {
	out := []graph.Asset{}
	for _, a := range g.Assets {
		if a.Type == kind {
			out = append(out, a)
			if len(out) >= limit {
				break
			}
		}
	}

	return out, nil
}

func (g FakeGraph) Edges(_ context.Context, id, dir, label string, _ time.Time) ([]graph.Relation, error) {
	out := []graph.Relation{}
	for _, r := range g.Links {
		if label != "" && r.Label != label {
			continue
		}
		if (dir == "out" || dir == "both") && r.FromID == id {
			out = append(out, r)
		} else if (dir == "in" || dir == "both") && r.ToID == id {
			out = append(out, r)
		}
	}

	return out, nil
}

func (g FakeGraph) EdgesLimited(ctx context.Context, id, dir, label string, since time.Time, limit int) ([]graph.Relation, bool, error) {
	// Enforce the repositories' limit so tests catch oversized reads.
	if limit < 1 || limit > graph.MaxEdgeRead {
		return nil, false, errors.New("edge limit must be 1..500")
	}

	edges, err := g.Edges(ctx, id, dir, label, since)
	if err != nil {
		return nil, false, err
	}
	if len(edges) > limit {
		return edges[:limit], true, nil
	}

	return edges, false, nil
}

func (g FakeGraph) EdgeEvidence(ctx context.Context, id string, limit int) ([]graph.Evidence, error) {
	return g.Evidence(ctx, id, limit)
}

func (g FakeGraph) Evidence(_ context.Context, id string, limit int) ([]graph.Evidence, error) {
	v := g.EvidenceByID[id]
	if len(v) > limit {
		v = v[:limit]
	}

	return v, nil
}

func SampleGraph() FakeGraph {
	return FakeGraph{
		Assets: map[string]graph.Asset{
			"a": {ID: "a", Type: "Organization", Key: "Acme"},
			"b": {ID: "b", Type: "FQDN", Key: "acme.example"},
			"c": {ID: "c", Type: "Service", Key: "svc"},
		},
		Links: []graph.Relation{
			{ID: "e1", FromID: "a", ToID: "b", Label: "website"},
			{ID: "e2", FromID: "b", ToID: "c", Label: "port"},
		},
	}
}
