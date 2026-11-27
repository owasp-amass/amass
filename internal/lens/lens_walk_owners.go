// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"encoding/json"
	"fmt"
	"sort"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// WitnessOf orients a stored edge between a and b as it is stored.
func WitnessOf(e graph.Relation, a, b graph.Asset) graph.WitnessEdge {
	from, to := a, b
	if e.FromID == b.ID {
		from, to = b, a
	}

	return graph.WitnessEdge{EdgeID: e.ID, Label: e.Label, RelationType: e.Type, FromID: from.ID, FromType: from.Type,
		From: graph.AssetLabel(from), ToID: to.ID, ToType: to.Type, To: graph.AssetLabel(to), Detail: RelationDetail(e)}
}

// RelationDetail summarizes the fields a stored relation carries beyond
// its label, such as a port number and protocol ("443/tcp").
func RelationDetail(e graph.Relation) string {
	data, err := json.Marshal(e.Content)
	if err != nil {
		return ""
	}

	var f struct {
		Port     int    `json:"port_number"`
		Protocol string `json:"protocol"`
	}
	if json.Unmarshal(data, &f) != nil {
		return ""
	}
	if f.Port > 0 {
		if f.Protocol != "" {
			return fmt.Sprintf("%d/%s", f.Port, f.Protocol)
		}

		return fmt.Sprint(f.Port)
	}

	return ""
}

// PathWitness returns the edges of a witnessed path.
func PathWitness(p graph.PlanMatch) []graph.WitnessEdge {
	out := make([]graph.WitnessEdge, 0, len(p.Edges))
	for i, e := range p.Edges {
		if i+1 < len(p.Nodes) {
			out = append(out, WitnessOf(e, p.Nodes[i], p.Nodes[i+1]))
		}
	}

	return out
}

// link records how a search reached an asset.
type link struct {
	parent graph.Asset
	edge   graph.Relation
	depth  int
}

// controller is the result of a controller search from one asset.
// undetermined is set when the search stopped at its step or read limit
// with paths left and no owner found: it is inconclusive, not evidence that
// no one controls the asset.
type controller struct {
	orgs         []graph.Asset
	visited      []graph.Asset
	own          bool
	undetermined bool
	links        map[string]link
}

// witness returns the edges from the search's start to id.
func (c controller) witness(id string, assets map[string]graph.Asset) []graph.WitnessEdge {
	var out []graph.WitnessEdge
	for cur := id; ; {
		l, ok := c.links[cur]
		if !ok {
			break
		}

		out = append([]graph.WitnessEdge{WitnessOf(l.edge, l.parent, assets[cur])}, out...)
		cur = l.parent.ID
	}

	return out
}

// controllerOf searches from a toward the Organization that controls it
// along ownerPass (see resolveControllers).
func (w *lensWalker) controllerOf(a graph.Asset, owned map[string]graph.Asset) (controller, error) {
	if err := w.resolveControllers([]graph.Asset{a}, owned); err != nil {
		return controller{}, err
	}

	return w.controllers[a.ID], nil
}

// fanoutCost is the extra depth of a step that is one of n steps of the same
// kind (label and destination type) leaving an asset: the base-2 logarithm
// of n, rounded up, so a single step costs nothing, one of 2 costs 1, one of
// 300 (a host's pages) costs 9 and one of 65,536 (a /16's addresses) 16. A
// search ranked by type distance alone would expand all of a host's pages,
// each one step from an Organization's website edge, before the host's
// registration record, and run out of owner steps on the way.
func fanoutCost(n int) int {
	cost := 0
	for m := 1; m < n; m *= 2 {
		cost++
	}
	return cost
}

// ownerItem is an asset waiting in an owner search's frontier.
type ownerItem struct {
	asset graph.Asset
	depth int
	dist  int
}

// ownerSearch is one controller search in progress.
type ownerSearch struct {
	start    graph.Asset
	c        controller
	seen     map[string]bool
	frontier []ownerItem
	best     int
	pops     int
	done     bool
	// cut is set when the run's read limit stopped the search.
	cut bool
}

// resolveControllers searches from each asset toward the Organization that
// controls it along ownerPass and caches the results (w.controllers). Each
// search goes best first by depth plus the type distance to an
// Organization, a step's depth growing with how many steps of its kind leave
// the same asset (fanoutCost), so a host's registration record is read
// before its hundreds of pages and a netblock's before its addresses. A search expands all its equally ranked assets
// as one round, and every search's round is read together in one step read
// (graph.StepsFrom) of only the edges an owner is reached along. A search
// stops at its closest Organizations, when it reaches an asset in owned
// (then own is set), or once it has expanded the walker's owner steps; a
// round under way when the budget runs out is finished. A search the steps
// or the read limit stop with paths left and no owner found is marked
// undetermined.
func (w *lensWalker) resolveControllers(assets []graph.Asset, owned map[string]graph.Asset) error {
	var active []*ownerSearch
	queued := map[string]bool{}
	for _, a := range assets {
		if _, ok := w.controllers[a.ID]; ok || queued[a.ID] {
			continue
		}

		queued[a.ID] = true
		active = append(active, &ownerSearch{start: a, c: controller{links: map[string]link{}},
			seen: map[string]bool{a.ID: true}, frontier: []ownerItem{w.rankOwner(a, 0)}, best: -1})
	}

	for len(active) > 0 {
		if err := w.ctx.Err(); err != nil {
			return err
		}

		rounds := make([][]graph.Asset, len(active))
		var ids []string
		for i, s := range active {
			rounds[i] = w.ownerRound(s, owned)
			for _, a := range rounds[i] {
				ids = append(ids, a.ID)
			}
		}

		next, ok, err := w.ownerNext(ids)
		if err != nil {
			return err
		}

		var still []*ownerSearch
		for i, s := range active {
			if !ok {
				s.done, s.cut = true, true
			}
			for _, cur := range rounds[i] {
				if s.done {
					break
				}
				depth := s.c.links[cur.ID].depth
				kinds := map[string]int{}
				for _, st := range next[cur.ID] {
					kinds[st.edge.Label+"|"+st.other.Type]++
				}
				for _, st := range next[cur.ID] {
					if s.seen[st.other.ID] {
						continue
					}

					d := depth + 1 + fanoutCost(kinds[st.edge.Label+"|"+st.other.Type])
					s.seen[st.other.ID] = true
					s.c.links[st.other.ID] = link{parent: cur, edge: st.edge, depth: d}
					s.frontier = append(s.frontier, w.rankOwner(st.other, d))
				}
			}
			if s.done || len(s.frontier) == 0 || s.pops >= w.ownerSteps {
				// stopped by a limit with paths left and no owner found
				limited := s.cut || (!s.done && len(s.frontier) > 0)
				s.c.undetermined = limited && !s.c.own && len(s.c.orgs) == 0
				sort.Slice(s.c.orgs, func(i, j int) bool {
					return graph.AssetLabel(s.c.orgs[i]) < graph.AssetLabel(s.c.orgs[j])
				})
				w.controllers[s.start.ID] = s.c
				continue
			}
			still = append(still, s)
		}
		active = still
	}

	return nil
}

// rankOwner ranks an asset for an owner search's frontier.
func (w *lensWalker) rankOwner(a graph.Asset, depth int) ownerItem {
	d, ok := w.ownerDist[a.Type]
	if !ok {
		d = len(w.ownerDist)
	}

	return ownerItem{asset: a, depth: depth, dist: d}
}

// ownerRound takes the search's next round from its frontier, all items
// with the least depth plus distance, closest to an Organization first,
// and returns the assets in it to expand. An Organization in the round is
// recorded and not expanded; an asset in owned ends the search with own
// set. The search is done when no round ranks as well as the closest
// Organization found.
func (w *lensWalker) ownerRound(s *ownerSearch, owned map[string]graph.Asset) []graph.Asset {
	score := -1
	for _, it := range s.frontier {
		if v := it.depth + it.dist; score < 0 || v < score {
			score = v
		}
	}
	if score < 0 || (s.best >= 0 && score > s.best) {
		s.done = true
		return nil
	}

	var round, rest []ownerItem
	for _, it := range s.frontier {
		if it.depth+it.dist == score {
			round = append(round, it)
		} else {
			rest = append(rest, it)
		}
	}
	s.frontier = rest
	sort.SliceStable(round, func(i, j int) bool {
		a, b := round[i], round[j]
		if a.dist != b.dist {
			return a.dist < b.dist
		}
		if la, lb := graph.AssetLabel(a.asset), graph.AssetLabel(b.asset); la != lb {
			return la < lb
		}
		return a.asset.ID < b.asset.ID
	})

	var expand []graph.Asset
	for _, it := range round {
		s.pops++
		s.c.visited = append(s.c.visited, it.asset)
		if _, mine := owned[it.asset.ID]; mine && it.asset.ID != s.start.ID {
			s.c.own, s.done = true, true
			return nil
		}
		if it.asset.Type == "Organization" {
			s.c.orgs = append(s.c.orgs, it.asset)
			s.best = score
			continue
		}

		expand = append(expand, it.asset)
	}

	return expand
}

// ownerStepList are the steps an owner search moves along (ownerPass),
// compiled from the catalog: never into a Person, and only into types an
// Organization can be reached from (ownerDist).
func (w *lensWalker) ownerStepList() ([]graph.Step, graph.StepSet) {
	if w.ownerStepSet != nil {
		return w.ownerStepsCache, w.ownerStepSet
	}

	leads := func(t string) bool {
		_, ok := w.ownerDist[t]
		return ok && t != "Person"
	}
	out := []graph.Step{}
	for _, r := range w.relations {
		m, ok := w.meaning(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if !ok {
			continue
		}
		if leads(r.DestinationType) && ownerPass(step{forward: true, attr: m.Attribution, purpose: m.Purpose}) {
			out = append(out, graph.Step{FromType: r.SourceType, Label: r.Label, RelationType: r.RelationType,
				ToType: r.DestinationType, Forward: true})
		}
		if leads(r.SourceType) && ownerPass(step{forward: false, attr: m.Attribution, purpose: m.Purpose}) {
			out = append(out, graph.Step{FromType: r.SourceType, Label: r.Label, RelationType: r.RelationType,
				ToType: r.DestinationType})
		}
	}

	w.ownerStepsCache, w.ownerStepSet = out, graph.NewStepSet(out)
	return w.ownerStepsCache, w.ownerStepSet
}

// ownerNext returns, for each of ids, the steps an owner search moves along
// from it, in a stable order and never across a shared platform's host. The
// edges of assets not read before are read in one step read, so only those
// edges are read, and kept for later searches. ok is false when the run is
// out of reads.
func (w *lensWalker) ownerNext(ids []string) (map[string][]step, bool, error) {
	steps, set := w.ownerStepList()
	var need []string
	want := map[string]bool{}
	for _, id := range ids {
		if _, read := w.ownerEdges[id]; !read && !want[id] {
			want[id] = true
			need = append(need, id)
		}
	}
	if len(need) > 0 {
		if w.outOfReads() {
			w.truncate("database read limit")
			return nil, false, nil
		}

		w.report.Reads++
		edges, err := graph.StepsFrom(w.ctx, w.graph, need, steps)
		if err != nil {
			return nil, false, err
		}
		if err := w.readAssets(edges); err != nil {
			return nil, false, err
		}
		if w.ownerEdges == nil {
			w.ownerEdges = map[string][]graph.Relation{}
		}
		for _, id := range need {
			w.ownerEdges[id] = nil
		}
		for _, e := range edges {
			if want[e.FromID] {
				w.ownerEdges[e.FromID] = append(w.ownerEdges[e.FromID], e)
			}
			if want[e.ToID] && e.ToID != e.FromID {
				w.ownerEdges[e.ToID] = append(w.ownerEdges[e.ToID], e)
			}
		}
	}

	out := make(map[string][]step, len(ids))
	for _, id := range ids {
		cur := w.assets[id]
		var found []step
		for _, e := range w.ownerEdges[id] {
			forward := e.FromID == id
			otherID := e.ToID
			if !forward {
				otherID = e.FromID
			}
			if otherID == "" || otherID == id {
				continue
			}

			other := w.assets[otherID]
			from, to := cur, other
			if !forward {
				from, to = other, cur
			}
			if s := (step{edge: e, other: other, forward: forward}); set.Follows(e, from.Type, to.Type, forward) &&
				!platformStep(cur, s) {
				found = append(found, s)
			}
		}
		sort.SliceStable(found, func(i, j int) bool {
			a, b := found[i].other, found[j].other
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			if la, lb := graph.AssetLabel(a), graph.AssetLabel(b); la != lb {
				return la < lb
			}
			return a.ID < b.ID
		})
		out[id] = found
	}

	return out, true, nil
}

// owningOrganizations returns the closest Organizations documented as
// controlling root, so that a domain question also covers its registrant's
// assets. It searches breadth first along ownerPass, a level at a time up
// to the walker's owner depth, reading each level's edges in one step read,
// so the nearest owner is found however many certificates and URLs share
// the subject's name.
func (w *lensWalker) owningOrganizations(root graph.Asset) ([]graph.Asset, error) {
	if root.Type == "Organization" {
		return nil, nil
	}

	var orgs []graph.Asset
	seen := map[string]bool{root.ID: true}
	frontier := []graph.Asset{root}
	for depth := 0; depth < w.ownerDepth && len(frontier) > 0 && len(orgs) == 0; depth++ {
		if err := w.ctx.Err(); err != nil {
			return nil, err
		}

		ids := make([]string, 0, len(frontier))
		for _, cur := range frontier {
			ids = append(ids, cur.ID)
		}
		next, ok, err := w.ownerNext(ids)
		if err != nil {
			return nil, err
		}
		if !ok {
			break
		}

		var level []graph.Asset
		for _, id := range ids {
			for _, s := range next[id] {
				if seen[s.other.ID] {
					continue
				}

				seen[s.other.ID] = true
				if s.other.Type == "Organization" {
					orgs = append(orgs, s.other)
					continue
				}
				level = append(level, s.other)
			}
		}
		frontier = level
	}

	sort.Slice(orgs, func(i, j int) bool { return graph.AssetLabel(orgs[i]) < graph.AssetLabel(orgs[j]) })
	return orgs, nil
}
