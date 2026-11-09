// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package ai provides model-independent, read-only OAM graph investigation.
package ai

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

type Asset struct {
	ID        string    `json:"id"`
	Type      string    `json:"type"`
	Key       string    `json:"key"`
	Content   any       `json:"content,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}
type Relation struct {
	ID        string    `json:"id"`
	FromID    string    `json:"from_id"`
	ToID      string    `json:"to_id"`
	Label     string    `json:"label"`
	Type      string    `json:"type"`
	Direction string    `json:"direction,omitempty"`
	CreatedAt time.Time `json:"created_at"`
	LastSeen  time.Time `json:"last_seen"`
}
type Evidence struct {
	ID        string    `json:"id"`
	SubjectID string    `json:"subject_id"`
	SourceID  string    `json:"source_id,omitempty"`
	Kind      string    `json:"kind"`
	Property  any       `json:"property,omitempty"`
	LastSeen  time.Time `json:"last_seen"`
}

// Graph is the only data interface available to an agent. No mutations or raw SQL.
type Graph interface {
	GetAsset(context.Context, string) (Asset, error)
	FindAssets(context.Context, string, time.Time, int) ([]Asset, error)
	Edges(context.Context, string, string, string, time.Time) ([]Relation, error)
	Evidence(context.Context, string, int) ([]Evidence, error)
}

// OrganizationLookup resolves an exact organization name using repository
// content queries rather than enumerating an arbitrary first page of assets.
// Callers must handle zero and multiple matching organizations explicitly.
type OrganizationLookup interface {
	LookupOrganizations(context.Context, string, int) ([]Asset, error)
}

// OrganizationResolver exposes bounded, provenance-labeled entity candidates.
type OrganizationResolver interface {
	ResolveOrganizations(context.Context, OrganizationQuery, int) (OrganizationResolution, error)
}

// BoundedGraph is the database-backed capability required by agent walks.
// Unsupported repositories fail closed rather than materializing all edges.
// EdgeEvidenceReader disambiguates relation tags from asset tags, even when
// asset IDs and edge IDs happen to share the same string representation.
type EdgeEvidenceReader interface {
	EdgeEvidence(context.Context, string, int) ([]Evidence, error)
}

type BoundedGraph interface {
	EdgesLimited(context.Context, string, string, string, time.Time, int) ([]Relation, bool, error)
}

type Limits struct {
	MaxDepth     int
	MaxNodes     int
	MaxEdges     int
	MaxPerNode   int
	MaxFind      int
	MaxEvidence  int
	MaxToolCalls int
	MaxToolBytes int
}

func DefaultLimits() Limits {
	return Limits{MaxDepth: 16, MaxNodes: 100, MaxEdges: 200, MaxPerNode: 40, MaxFind: 50,
		MaxEvidence: 50, MaxToolCalls: 10, MaxToolBytes: 64000}
}
func (l Limits) Validate() error {
	if l.MaxDepth < 1 || l.MaxDepth > 32 || l.MaxNodes < 1 || l.MaxNodes > 2000 ||
		l.MaxEdges < 1 || l.MaxEdges > 4000 || l.MaxPerNode < 1 || l.MaxPerNode > 500 ||
		l.MaxFind < 1 || l.MaxFind > 1000 || l.MaxEvidence < 1 || l.MaxEvidence > 500 ||
		l.MaxToolCalls < 1 || l.MaxToolCalls > 40 || l.MaxToolBytes < 1024 || l.MaxToolBytes > 1048576 {
		return errors.New("limits outside approved bounds")
	}
	return nil
}

type WalkRequest struct {
	StartID   string `json:"start_id"`
	Direction string `json:"direction,omitempty"`
	Label     string `json:"label,omitempty"`
	Depth     int    `json:"depth,omitempty"`
	Since     string `json:"since,omitempty"`
}
type WalkResult struct {
	Nodes     []Asset    `json:"nodes"`
	Edges     []Relation `json:"edges"`
	Truncated bool       `json:"truncated"`
	Reason    string     `json:"reason,omitempty"`
}

func DateSince(s string) (time.Time, error) {
	if strings.TrimSpace(s) == "" {
		return time.Time{}, nil
	}
	t, e := time.Parse(time.RFC3339, s)
	if e != nil {
		return time.Time{}, fmt.Errorf("since must be RFC3339: %w", e)
	}
	return t, nil
}

// Walk uses BFS with a deterministic visit order for bounded graph expansion.
func Walk(ctx context.Context, graph Graph, l Limits, r WalkRequest) (WalkResult, error) {
	var out WalkResult
	if err := l.Validate(); err != nil {
		return out, err
	}
	if r.StartID == "" {
		return out, errors.New("start_id required")
	}
	if r.Depth == 0 {
		r.Depth = 1
	}
	if r.Depth < 1 || r.Depth > l.MaxDepth {
		return out, errors.New("depth exceeds policy")
	}
	if r.Direction == "" {
		r.Direction = "both"
	}
	if r.Direction != "both" && r.Direction != "in" && r.Direction != "out" {
		return out, errors.New("direction must be in, out or both")
	}
	since, err := DateSince(r.Since)
	if err != nil {
		return out, err
	}
	limited, ok := graph.(BoundedGraph)
	if !ok {
		return out, errors.New("graph repository lacks bounded edge queries")
	}
	a, err := graph.GetAsset(ctx, r.StartID)
	if err != nil {
		return out, err
	}
	out.Nodes = append(out.Nodes, a)
	type item struct {
		id    string
		depth int
	}
	queue := []item{{r.StartID, 0}}
	seen := map[string]bool{r.StartID: true}
	edgeIDs := map[string]bool{}
	for len(queue) > 0 {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		current := queue[0]
		queue = queue[1:]
		if current.depth >= r.Depth {
			continue
		}
		edges, more, err := limited.EdgesLimited(ctx, current.id, r.Direction, r.Label, since, l.MaxPerNode)
		if err != nil {
			return out, err
		}
		if len(edges) > l.MaxPerNode {
			return out, errors.New("bounded graph adapter violated row limit")
		}
		if more {
			out.Truncated = true
			out.Reason = "per-node edge limit"
		}
		for _, edge := range edges {
			if !edgeIDs[edge.ID] {
				if len(out.Edges) >= l.MaxEdges {
					out.Truncated = true
					out.Reason = "edge limit"
					return out, nil
				}
				edgeIDs[edge.ID] = true
				out.Edges = append(out.Edges, edge)
			}
			nextID := edge.ToID
			if current.id == edge.ToID {
				nextID = edge.FromID
			}
			if seen[nextID] {
				continue
			}
			if len(out.Nodes) >= l.MaxNodes {
				out.Truncated = true
				out.Reason = "node limit"
				return out, nil
			}
			next, err := graph.GetAsset(ctx, nextID)
			if err != nil {
				return out, err
			}
			seen[nextID] = true
			out.Nodes = append(out.Nodes, next)
			queue = append(queue, item{nextID, current.depth + 1})
		}
	}
	return out, nil
}
