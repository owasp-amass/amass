// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// GuidedSearchRequest extends bounded graph search with ranked relation hints
// and multiple independent simple paths to the same destination asset.
type GuidedSearchRequest struct {
	GraphSearchRequest
	PreferredLabels  []string
	MaxPathsPerAsset int
	MaxExpansions    int
	Relationships    []GoalRelation
	PathRule         string
}

type GuidedFrontier struct {
	AssetID         string   `json:"asset_id"`
	AssetType       string   `json:"asset_type"`
	Depth           int      `json:"depth"`
	PathID          string   `json:"path_id"`
	AvailableLabels []string `json:"available_labels"`
}

type guidedPath struct {
	match PlanMatch
	score int
}

type guidedEdgeBatch struct {
	edges []Relation
	more  bool
}

// GuidedExplorer supports incremental, schema-validated expansion. Each
// frontier entry represents a distinct simple path, not a globally visited
// node. This preserves alternative routes while prohibiting cycles within
// a path. No path or model hint can bypass resource budgets.
type GuidedExplorer struct {
	graph         Graph
	bounded       BoundedGraph
	limits        Limits
	req           GuidedSearchRequest
	catalog       map[string]bool
	out           GraphSearchResult
	frontier      []guidedPath
	assets        map[string]Asset
	edgeCache     map[string]guidedEdgeBatch
	seenEdge      map[string]bool
	seenPath      map[string]bool
	perAsset      map[string]int
	targets       map[string]bool
	knownTypes    map[string]bool
	labels        map[string]bool
	typeDistances map[string]int
	preferred     []string
	preferAssets  map[string]bool
	preferPaths   map[string]bool
	expanded      int
	matches       int
	alternates    int
	since         time.Time
	finished      bool
}

// WitnessPathID is derived only from real asset and edge identifiers. It is
// stable for a given directed traversal path and does not assert ownership.
func WitnessPathID(match PlanMatch) string {
	var s strings.Builder
	for i, n := range match.Nodes {
		s.WriteString(n.ID)
		s.WriteByte(0)
		if i < len(match.Edges) {
			e := match.Edges[i]
			s.WriteString(e.ID)
			s.WriteByte(0)
		}
	}
	sum := sha256.Sum256([]byte(s.String()))
	return hex.EncodeToString(sum[:12])
}

func NewGuidedExplorer(ctx context.Context, graph Graph, catalog SchemaCatalog, limits Limits, req GuidedSearchRequest) (*GuidedExplorer, error) {
	if err := limits.Validate(); err != nil {
		return nil, err
	}
	if graph == nil || catalog == nil {
		return nil, errors.New("graph and OAM schema catalog required")
	}
	bounded, ok := graph.(BoundedGraph)
	if !ok {
		return nil, errors.New("graph repository lacks bounded edge queries")
	}
	if req.StartID == "" {
		return nil, errors.New("start_id required")
	}
	if req.Direction == "" {
		req.Direction = "both"
	}
	if req.Direction != "in" && req.Direction != "out" && req.Direction != "both" {
		return nil, errors.New("invalid graph direction")
	}
	if req.MaxDepth == 0 {
		req.MaxDepth = limits.MaxDepth
	}
	if req.MaxDepth < 1 || req.MaxDepth > limits.MaxDepth {
		return nil, errors.New("max_depth exceeds policy")
	}
	if req.MaxMatches == 0 {
		req.MaxMatches = min(20, limits.MaxFind)
	}
	if req.MaxMatches < 1 || req.MaxMatches > limits.MaxFind {
		return nil, errors.New("max_matches exceeds policy")
	}
	if req.MaxPathsPerAsset == 0 {
		req.MaxPathsPerAsset = 3
	}
	if req.MaxPathsPerAsset < 1 || req.MaxPathsPerAsset > 8 {
		return nil, errors.New("max_paths_per_asset must be 1..8")
	}
	if req.MaxExpansions == 0 {
		req.MaxExpansions = min(200, limits.MaxNodes*req.MaxPathsPerAsset)
	}
	if req.MaxExpansions < 1 || req.MaxExpansions > min(400, limits.MaxNodes*8) {
		return nil, errors.New("max_expansions exceeds policy")
	}
	since, err := DateSince(req.Since)
	if err != nil {
		return nil, err
	}
	root, err := graph.GetAsset(ctx, req.StartID)
	if err != nil {
		return nil, err
	}
	s := &GuidedExplorer{
		graph: graph, bounded: bounded, limits: limits, req: req, since: since,
		catalog: map[string]bool{}, targets: map[string]bool{}, labels: map[string]bool{},
		knownTypes: map[string]bool{}, typeDistances: map[string]int{},
		assets: map[string]Asset{root.ID: root}, edgeCache: map[string]guidedEdgeBatch{},
		seenEdge: map[string]bool{}, seenPath: map[string]bool{},
		perAsset: map[string]int{root.ID: 1}, preferAssets: map[string]bool{}, preferPaths: map[string]bool{},
		out: GraphSearchResult{Root: root, Matches: []PlanMatch{}, Mode: "guided"},
	}
	for _, t := range catalog.Relations() {
		s.catalog[t.SourceType+"\x00"+t.Label+"\x00"+t.RelationType+"\x00"+t.DestinationType] = true
		s.knownTypes[t.SourceType] = true
		s.knownTypes[t.DestinationType] = true
		s.labels[t.Label] = true
	}
	if selectors, ok := catalog.(AssetSearchCatalog); ok {
		for _, item := range selectors.SearchFields() {
			s.knownTypes[item.Type] = true
		}
	}
	if !s.knownTypes[root.Type] {
		return nil, fmt.Errorf("unregistered OAM root type %q", root.Type)
	}
	if len(req.TargetTypes) > 100 {
		return nil, errors.New("too many target types")
	}
	for _, t := range req.TargetTypes {
		if !s.knownTypes[t] {
			return nil, fmt.Errorf("unregistered target OAM type %q", t)
		}
		s.targets[t] = true
	}
	if err := validGoalRelations(req.Relationships, req.PathRule, catalog.Relations()); err != nil {
		return nil, err
	}
	if err := s.Focus(req.PreferredLabels, nil); err != nil {
		return nil, err
	}
	// Precompute an undirected type-distance heuristic. A type absent from
	// the shortest schema route is not excluded: actual edges remain decisive.
	for t := range s.targets {
		s.typeDistances[t] = 0
	}
	for changed := true; changed; {
		changed = false
		for _, rel := range catalog.Relations() {
			for _, pair := range [][2]string{{rel.SourceType, rel.DestinationType}, {rel.DestinationType, rel.SourceType}} {
				if distance, ok := s.typeDistances[pair[1]]; ok {
					if prior, ok := s.typeDistances[pair[0]]; !ok || distance+1 < prior {
						s.typeDistances[pair[0]] = distance + 1
						changed = true
					}
				}
			}
		}
	}
	initial := PlanMatch{Nodes: []Asset{root}, Edges: []Relation{}}
	initial.PathID = WitnessPathID(initial)
	s.frontier = []guidedPath{{match: initial}}
	s.seenPath[initial.PathID] = true
	return s, nil
}

// Focus updates priorities only. It never narrows the taxonomy, omits a
// branch, or grants permission to collect data from the Internet.
func (s *GuidedExplorer) Focus(labels []string, assetIDs []string) error {
	return s.FocusAll(labels, assetIDs, nil)
}

// FocusPaths retains existing label/asset priorities while switching to a
// specified set of exact, already-witnessed frontier paths.
func (s *GuidedExplorer) FocusPaths(ids []string) error {
	assets := make([]string, 0, len(s.preferAssets))
	for id := range s.preferAssets {
		assets = append(assets, id)
	}
	return s.FocusAll(s.preferred, assets, ids)
}

// FocusAll validates the entire recommendation before applying any change.
// Invalid model advice therefore cannot partially alter frontier ranking.
func (s *GuidedExplorer) FocusAll(labels, assetIDs, pathIDs []string) error {
	for _, label := range labels {
		if !s.labels[label] {
			return fmt.Errorf("unknown OAM relationship label %q", label)
		}
	}
	pendingAssets := map[string]bool{}
	pendingPaths := map[string]bool{}
	for _, entry := range s.frontier {
		pendingAssets[entry.match.Nodes[len(entry.match.Nodes)-1].ID] = true
		pendingPaths[entry.match.PathID] = true
	}
	for _, id := range assetIDs {
		if !pendingAssets[id] {
			return fmt.Errorf("priority asset %q not in current frontier", id)
		}
	}
	for _, id := range pathIDs {
		if !pendingPaths[id] {
			return fmt.Errorf("priority path %q not in current frontier", id)
		}
	}
	s.preferred = append([]string(nil), labels...)
	s.preferAssets = map[string]bool{}
	for _, id := range assetIDs {
		s.preferAssets[id] = true
	}
	s.preferPaths = map[string]bool{}
	for _, id := range pathIDs {
		s.preferPaths[id] = true
	}
	return nil
}

func (s *GuidedExplorer) priority(path guidedPath) int {
	score := 0
	last := path.match.Nodes[len(path.match.Nodes)-1]
	if d, ok := s.typeDistances[last.Type]; ok {
		score += 40 - 4*d
	}
	for _, edge := range path.match.Edges {
		for i, label := range s.preferred {
			if edge.Label == label {
				score += 15 - min(10, i*2)
				break
			}
		}
	}
	if s.preferAssets[last.ID] {
		score += 80
	}
	if s.preferPaths[path.match.PathID] {
		score += 120
	}
	score -= len(path.match.Edges) * 3
	return score
}

func (s *GuidedExplorer) Pending(limit int) []GuidedFrontier {
	if limit <= 0 {
		return nil
	}
	ordered := append([]guidedPath(nil), s.frontier...)
	sort.SliceStable(ordered, func(i, j int) bool {
		a, b := s.priority(ordered[i]), s.priority(ordered[j])
		if a != b {
			return a > b
		}
		return ordered[i].match.PathID < ordered[j].match.PathID
	})
	out := make([]GuidedFrontier, 0, min(limit, len(ordered)))
	for _, entry := range ordered {
		if len(out) >= limit {
			break
		}
		node := entry.match.Nodes[len(entry.match.Nodes)-1]
		var labels []string
		if edges, ok := s.edgeCache[node.ID]; ok {
			seen := map[string]bool{}
			for _, e := range edges.edges {
				seen[e.Label] = true
			}
			for label := range seen {
				labels = append(labels, label)
			}
			sort.Strings(labels)
		}
		out = append(out, GuidedFrontier{AssetID: node.ID, AssetType: node.Type, Depth: len(entry.match.Edges), PathID: entry.match.PathID, AvailableLabels: labels})
	}
	return out
}

func (s *GuidedExplorer) end(reason string) {
	s.out.Truncated = true
	if s.out.Reason == "" {
		s.out.Reason = reason
	}
	s.finished = true
}

func containsPathAsset(p PlanMatch, id string) bool {
	for _, n := range p.Nodes {
		if n.ID == id {
			return true
		}
	}
	return false
}

// Advance expands at most batch paths, or all currently pending paths when
// batch <= 0. Result.Exhausted is only true after the bounded frontier drains.
func (s *GuidedExplorer) Advance(ctx context.Context, batch int) (bool, error) {
	if s.finished {
		return true, nil
	}
	count := 0
	for len(s.frontier) > 0 && (batch <= 0 || count < batch) {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		if s.expanded >= s.req.MaxExpansions {
			s.end("path expansion limit")
			break
		}
		sort.SliceStable(s.frontier, func(i, j int) bool {
			a, b := s.priority(s.frontier[i]), s.priority(s.frontier[j])
			if a != b {
				return a > b
			}
			return s.frontier[i].match.PathID < s.frontier[j].match.PathID
		})
		current := s.frontier[0]
		s.frontier = s.frontier[1:]
		count++
		s.expanded++
		if len(current.match.Edges) >= s.req.MaxDepth {
			continue
		}
		node := current.match.Nodes[len(current.match.Nodes)-1]
		batchEdges, ok := s.edgeCache[node.ID]
		if !ok {
			edges, more, err := s.bounded.EdgesLimited(ctx, node.ID, s.req.Direction, "", s.since, s.limits.MaxPerNode)
			if err != nil {
				return false, err
			}
			if len(edges) > s.limits.MaxPerNode {
				return false, errors.New("bounded repository exceeded per-node edge policy")
			}
			sort.SliceStable(edges, func(i, j int) bool { return edges[i].ID < edges[j].ID })
			batchEdges = guidedEdgeBatch{edges: edges, more: more}
			s.edgeCache[node.ID] = batchEdges
			if more {
				s.out.Truncated = true
				if s.out.Reason == "" {
					s.out.Reason = "per-node edge limit"
				}
			}
		}
		for _, e := range batchEdges.edges {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			nextID := ""
			switch {
			case e.FromID == node.ID && s.req.Direction != "in":
				nextID = e.ToID
			case e.ToID == node.ID && s.req.Direction != "out":
				nextID = e.FromID
			default:
				return false, fmt.Errorf("edge %q not incident in requested direction", e.ID)
			}
			if !s.seenEdge[e.ID] {
				if len(s.seenEdge) >= s.limits.MaxEdges {
					s.end("edge limit")
					return true, nil
				}
				s.seenEdge[e.ID] = true
			}
			if containsPathAsset(current.match, nextID) {
				continue
			}
			next, ok := s.assets[nextID]
			if !ok {
				if len(s.assets) >= s.limits.MaxNodes {
					s.end("node limit")
					return true, nil
				}
				var err error
				next, err = s.graph.GetAsset(ctx, nextID)
				if err != nil {
					return false, err
				}
				s.assets[nextID] = next
			}
			source, dest := node.Type, next.Type
			if e.FromID == nextID {
				source, dest = dest, source
			}
			if !s.catalog[source+"\x00"+e.Label+"\x00"+e.Type+"\x00"+dest] {
				s.out.SchemaRejected++
				continue
			}
			if s.perAsset[nextID] >= s.req.MaxPathsPerAsset {
				s.out.AlternativePathsSkipped++
				continue
			}
			path := PlanMatch{
				Nodes: append(append([]Asset(nil), current.match.Nodes...), next),
				Edges: append(append([]Relation(nil), current.match.Edges...), e),
			}
			path.PathID = WitnessPathID(path)
			if s.seenPath[path.PathID] {
				continue
			}
			s.seenPath[path.PathID] = true
			s.perAsset[nextID]++
			s.frontier = append(s.frontier, guidedPath{match: path})
			if (len(s.targets) == 0 || s.targets[next.Type]) && pathSatisfiesGoal(path, s.req.Relationships, s.req.PathRule) {
				s.out.Matches = append(s.out.Matches, path)
				s.matches++
				if s.perAsset[nextID] > 1 {
					s.alternates++
				}
				if len(s.out.Matches) >= s.req.MaxMatches {
					s.end("match limit")
					return true, nil
				}
			}
		}
	}
	if len(s.frontier) == 0 {
		s.finished = true
	}
	return s.finished, nil
}

func (s *GuidedExplorer) Result() GraphSearchResult {
	out := s.out
	out.VisitedNodes = len(s.assets)
	out.VisitedEdges = len(s.seenEdge)
	out.ExpandedPaths = s.expanded
	out.AlternativeMatches = s.alternates
	if s.out.SchemaRejected > 0 && !out.Truncated {
		out.Truncated = true
		out.Reason = "stored edge absent from OAM taxonomy"
	}
	if s.out.AlternativePathsSkipped > 0 && !out.Truncated {
		out.Truncated = true
		out.Reason = "per-asset alternative path limit"
	}
	if s.finished && len(s.frontier) == 0 && !out.Truncated {
		out.Exhausted = true
	}
	return out
}
