// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// searchTypedRelationIntent executes the compiled route with server-side
// direction+label bounds. This avoids wasting the global match budget on
// unrelated URLs, DNS, TLS and other OAM graph neighbors.
func searchTypedRelationIntent(ctx context.Context, g graph.Graph, limits graph.Limits, root graph.Asset, intent TypedRelationIntent, opts AdaptiveOptions) (GraphSearchResult, error) {
	out := GraphSearchResult{Root: root, Matches: []graph.PlanMatch{}, Mode: "typed_relation_inventory"}
	if err := limits.Validate(); err != nil {
		return out, err
	}

	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return out, errors.New("bounded graph reader required")
	}
	if root.Type != intent.Goal.Subject.Type {
		return out, errors.New("resolved root type differs from intent subject")
	}
	if len(intent.Hops) < 1 || len(intent.Hops) > maxPlanHops {
		return out, errors.New("invalid typed intent hop count")
	}

	depth := opts.MaxDepth
	if depth == 0 {
		depth = limits.MaxDepth
	}
	if depth < 1 || depth > limits.MaxDepth {
		return out, errors.New("invalid depth")
	}
	if depth < len(intent.Hops) {
		out.Truncated = true
		out.Reason = "depth limit"
		out.VisitedNodes = 1
		return out, nil
	}

	maxMatches := opts.MaxMatches
	if maxMatches == 0 {
		maxMatches = min(20, limits.MaxFind)
	}
	if maxMatches < 1 || maxMatches > limits.MaxFind {
		return out, errors.New("max matches exceeds policy")
	}

	maxExpansions := opts.MaxExpansions
	if maxExpansions == 0 {
		maxExpansions = min(200, limits.MaxNodes)
	}
	if maxExpansions < 1 || maxExpansions > min(400, limits.MaxNodes*8) {
		return out, errors.New("max expansions exceeds policy")
	}

	paths := []graph.PlanMatch{{Nodes: []graph.Asset{root}}}
	seenNodes := map[string]bool{root.ID: true}
	seenEdges := map[string]bool{}
	seenMatches := map[string]bool{}
	for index, hop := range intent.Hops {
		previousType := root.Type
		if index > 0 {
			previousType = intent.Hops[index-1].DestinationType
		}

		diagnostic := GraphHopDiagnostic{
			Hop: index + 1, SourceType: previousType, TargetType: hop.DestinationType,
			Direction: hop.Direction, Label: hop.Label, RelationType: hop.RelationType,
			InputPaths: len(paths),
		}
		nextPaths := make([]graph.PlanMatch, 0)
		for _, path := range paths {
			if err := ctx.Err(); err != nil {
				return out, err
			}
			if out.ExpandedPaths >= maxExpansions {
				out.Truncated = true
				out.Reason = "path expansion limit"
				break
			}

			out.ExpandedPaths++
			diagnostic.QueriedPaths++
			last := path.Nodes[len(path.Nodes)-1]
			// The answer is computed here, so a hop reads as many edges as
			// matches were asked for, a page at a time, when that exceeds the
			// per-node limit meant for model context.
			perNode := limits.MaxPerNode
			var edges []graph.Relation
			var more bool
			var err error
			if _, paged := g.(graph.PagedGraph); paged && maxMatches+1 > perNode {
				perNode = maxMatches + 1
				edges, more, err = graph.ReadEdges(ctx, g, last.ID, hop.Direction, hop.Label, perNode,
					func() bool { return true })
			} else {
				edges, more, err = bounded.EdgesLimited(ctx, last.ID, hop.Direction, hop.Label, time.Time{}, perNode)
			}
			if err != nil {
				return out, err
			}

			diagnostic.ReturnedEdges += len(edges)
			if len(edges) > perNode {
				return out, errors.New("bounded graph exceeded per-node edge policy")
			}
			if more {
				out.Truncated = true
				if out.Reason == "" {
					out.Reason = "per-node edge limit"
				}
			}

			sort.Slice(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
			read, err := graph.FarAssets(ctx, g, last.ID, edges, nil)
			if err != nil {
				return out, err
			}
			for _, edge := range edges {
				if err := ctx.Err(); err != nil {
					return out, err
				}
				if edge.Label != hop.Label || edge.Type != hop.RelationType {
					out.SchemaRejected++
					continue
				}

				dest := ""
				if hop.Direction == "out" && edge.FromID == last.ID {
					dest = edge.ToID
				}
				if hop.Direction == "in" && edge.ToID == last.ID {
					dest = edge.FromID
				}
				if dest == "" {
					out.SchemaRejected++
					continue
				}

				cycle := false
				for _, node := range path.Nodes {
					if node.ID == dest {
						cycle = true
						break
					}
				}
				if cycle {
					continue
				}
				if !seenEdges[edge.ID] {
					if len(seenEdges) >= limits.MaxEdges {
						out.Truncated = true
						out.Reason = "edge limit"
						break
					}

					seenEdges[edge.ID] = true
				}
				if !seenNodes[dest] && len(seenNodes) >= limits.MaxNodes {
					out.Truncated = true
					out.Reason = "node limit"
					break
				}

				asset, err := graph.AssetFrom(ctx, g, read, dest)
				if err != nil {
					return out, err
				}
				if asset.Type != hop.DestinationType {
					out.SchemaRejected++
					continue
				}

				seenNodes[dest] = true
				diagnostic.AcceptedEdges++
				witness := graph.PlanMatch{
					Nodes: append(append([]graph.Asset(nil), path.Nodes...), asset),
					Edges: append(append([]graph.Relation(nil), path.Edges...), edge),
				}
				witness.PathID = graph.WitnessPathID(witness)
				if index == len(intent.Hops)-1 {
					if seenMatches[asset.ID] {
						continue
					}

					seenMatches[asset.ID] = true
					out.Matches = append(out.Matches, witness)
					if len(out.Matches) >= maxMatches {
						out.Truncated = true
						out.Reason = "match limit"
						break
					}
				} else {
					// A dense multi-hop graph may admit many paths between the same
					// bounded set of nodes. Cap the frontier independently from the
					// unique edge/node budgets to avoid unbounded intermediate memory.
					if len(nextPaths) >= limits.MaxEdges {
						out.Truncated = true
						out.Reason = "intermediate path limit"
						break
					}

					nextPaths = append(nextPaths, witness)
				}
			}
			if out.Reason == "match limit" || out.Reason == "edge limit" || out.Reason == "node limit" ||
				out.Reason == "intermediate path limit" {
				break
			}
		}

		diagnostic.Truncated = out.Truncated
		if index == len(intent.Hops)-1 {
			diagnostic.OutputPaths = len(out.Matches)
		} else {
			diagnostic.OutputPaths = len(nextPaths)
		}

		out.HopDiagnostics = append(out.HopDiagnostics, diagnostic)
		if out.Reason == "match limit" || out.Reason == "edge limit" || out.Reason == "node limit" ||
			out.Reason == "intermediate path limit" || out.Reason == "path expansion limit" {
			break
		}
		// Do not issue empty subsequent hops. Preserve the first failing hop
		// and keep the query complete when no limit or repository error occurred.
		if len(nextPaths) == 0 && index < len(intent.Hops)-1 {
			break
		}

		paths = nextPaths
	}

	out.VisitedNodes = len(seenNodes)
	out.VisitedEdges = len(seenEdges)
	out.Exhausted = !out.Truncated
	sort.Slice(out.Matches, func(i, j int) bool {
		a, b := out.Matches[i], out.Matches[j]
		x, y := a.Nodes[len(a.Nodes)-1], b.Nodes[len(b.Nodes)-1]
		if x.Key == y.Key {
			return a.PathID < b.PathID
		}

		return x.Key < y.Key
	})
	return out, nil
}
