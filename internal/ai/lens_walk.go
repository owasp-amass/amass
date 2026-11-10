// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// Lens bounds. Lens walks never send assets to a model, so these are
// database-cost limits rather than context limits.
const (
	lensMaxFootprint = 2000
	lensMaxPerAsset  = MaxEdgeRead
	lensMaxReads     = 20000
	lensMaxExamples  = 3
	// lensMaxOwnerPops bounds the controller search from one asset.
	lensMaxOwnerPops = 40
	// lensMaxOwnerDepth bounds the search for the subject's own owner.
	lensMaxOwnerDepth = 5
)

// purposeHierarchy marks same_subject edges that link a parent to a child
// (the FQDN node hierarchy). Control descends them; ownership ascends them.
const purposeHierarchy = "hierarchy"

// RelationMeaning is the semantics table entry for one OAM transition.
type RelationMeaning struct {
	Attribution string
	Purpose     string
	// Vendor is false when a third_party destination is registry or
	// protocol infrastructure (an abuse desk, RDAP, WHOIS or OCSP endpoint)
	// rather than a party the source depends on.
	Vendor bool
}

// SemanticsCatalog is implemented by schema catalogs that carry the full
// relationship semantics table (see internal/ai/semantics).
type SemanticsCatalog interface {
	Meaning(source, label, relationType, destination string) (RelationMeaning, bool)
}

type meaningFunc func(source, label, relationType, destination string) (RelationMeaning, bool)

// meaningsOf returns the semantics lookup of cat: the full table when cat
// is a SemanticsCatalog, otherwise attribution only (no purpose, every
// third party treated as a vendor). It returns nil without attribution.
func meaningsOf(cat any) meaningFunc {
	if s, ok := cat.(SemanticsCatalog); ok {
		return s.Meaning
	}
	if a, ok := cat.(AttributionCatalog); ok {
		return func(source, label, relationType, destination string) (RelationMeaning, bool) {
			attr, ok := a.Attribution(source, label, relationType, destination)
			return RelationMeaning{Attribution: attr, Vendor: true}, ok
		}
	}

	return nil
}

// footprintPass reports whether control passes from the expanded asset to
// the other end of s: same_subject edges (hierarchy edges only downward),
// controls edges forward and controller edges backward.
func footprintPass(s step) bool {
	switch s.attr {
	case attrSameSubject:
		return s.purpose != purposeHierarchy || s.forward
	case attrControls:
		return s.forward
	case attrController:
		return !s.forward
	}

	return false
}

// ownerPass reports whether s moves toward the party that controls the
// expanded asset: same_subject edges (hierarchy edges only upward),
// controller edges forward and controls edges backward.
func ownerPass(s step) bool {
	switch s.attr {
	case attrSameSubject:
		return s.purpose != purposeHierarchy || !s.forward
	case attrController:
		return s.forward
	case attrControls:
		return !s.forward
	}

	return false
}

// typeMoves builds the type-level graph of a pass rule from the catalog.
// pass is called with a synthetic step for each direction of each
// transition.
func typeMoves(relations []RelationshipSchema, meaning meaningFunc, pass func(step) bool) map[string]map[string]bool {
	moves := map[string]map[string]bool{}
	add := func(from, to string) {
		if moves[from] == nil {
			moves[from] = map[string]bool{}
		}

		moves[from][to] = true
	}
	for _, r := range relations {
		m, ok := meaning(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if !ok {
			continue
		}
		if pass(step{forward: true, attr: m.Attribution, purpose: m.Purpose}) {
			add(r.SourceType, r.DestinationType)
		}
		if pass(step{forward: false, attr: m.Attribution, purpose: m.Purpose}) {
			add(r.DestinationType, r.SourceType)
		}
	}

	return moves
}

// distanceTo returns, for every type, the fewest moves to reach target.
func distanceTo(moves map[string]map[string]bool, target string) map[string]int {
	reverse := map[string][]string{}
	for from, tos := range moves {
		for to := range tos {
			reverse[to] = append(reverse[to], from)
		}
	}

	dist := map[string]int{target: 0}
	queue := []string{target}
	for len(queue) > 0 {
		t := queue[0]
		queue = queue[1:]
		for _, from := range reverse[t] {
			if _, seen := dist[from]; !seen && from != "Person" {
				dist[from] = dist[t] + 1
				queue = append(queue, from)
			}
		}
	}

	return dist
}

// lensWalker reads the graph for one lens run, caching assets and edges and
// enforcing the read bounds.
type lensWalker struct {
	ctx       context.Context
	graph     Graph
	bounded   BoundedGraph
	meaning   meaningFunc
	relations []RelationshipSchema
	assets    map[string]Asset
	edges     map[string][]Relation
	report    *ThirdPartyReport
	// expand, when set, limits which controlled asset types are expanded
	// further; other controlled assets are recorded but not read.
	expand map[string]bool
	// parent and via record how each controlled asset was reached, so a
	// witnessed path can be rebuilt from the root.
	parent map[string]string
	via    map[string]Relation
	// ownerDist is the type distance to an Organization along ownerPass.
	ownerDist map[string]int
	// controllers caches controllerOf results by asset ID.
	controllers map[string]controller
}

func newLensWalker(ctx context.Context, graph Graph, bounded BoundedGraph, meaning meaningFunc, relations []RelationshipSchema, root Asset, report *ThirdPartyReport) *lensWalker {
	return &lensWalker{
		ctx:         ctx,
		graph:       graph,
		bounded:     bounded,
		meaning:     meaning,
		relations:   relations,
		assets:      map[string]Asset{root.ID: root},
		edges:       map[string][]Relation{},
		report:      report,
		ownerDist:   distanceTo(typeMoves(relations, meaning, ownerPass), "Organization"),
		controllers: map[string]controller{},
	}
}

func (w *lensWalker) truncate(reason string) {
	if !w.report.Truncated {
		w.report.Truncated = true
		w.report.Reason = reason
	}
}

func (w *lensWalker) asset(id string) (Asset, error) {
	if a, ok := w.assets[id]; ok {
		return a, nil
	}

	a, err := w.graph.GetAsset(w.ctx, id)
	if err != nil {
		return Asset{}, err
	}

	w.assets[id] = a
	return a, nil
}

// neighbors returns the stored edges in both directions for id, read once.
func (w *lensWalker) neighbors(id string) ([]Relation, error) {
	if e, ok := w.edges[id]; ok {
		return e, nil
	}

	var all []Relation
	for _, dir := range []string{"out", "in"} {
		if w.report.Reads >= lensMaxReads {
			w.truncate("database read limit")
			break
		}

		w.report.Reads++
		edges, more, err := w.bounded.EdgesLimited(w.ctx, id, dir, "", time.Time{}, lensMaxPerAsset)
		if err != nil {
			return nil, err
		}
		if more {
			a := w.assets[id]
			w.truncate(fmt.Sprintf("more than %d %s edges on %s %s", lensMaxPerAsset, dir, a.Type, assetLabel(a)))
		}

		all = append(all, edges...)
	}

	w.edges[id] = all
	return all, nil
}

// step is one stored edge seen from the asset being expanded, with its
// semantics.
type step struct {
	edge    Relation
	other   Asset
	forward bool
	attr    string
	purpose string
	vendor  bool
}

func (w *lensWalker) steps(cur Asset) ([]step, error) {
	edges, err := w.neighbors(cur.ID)
	if err != nil {
		return nil, err
	}

	out := make([]step, 0, len(edges))
	for _, e := range edges {
		forward := e.FromID == cur.ID
		otherID := e.ToID
		if !forward {
			otherID = e.FromID
		}
		if otherID == "" || otherID == cur.ID {
			continue
		}

		other, err := w.asset(otherID)
		if err != nil {
			return nil, err
		}

		src, dst := cur.Type, other.Type
		if !forward {
			src, dst = other.Type, cur.Type
		}

		m, ok := w.meaning(src, e.Label, e.Type, dst)
		if !ok {
			continue
		}

		out = append(out, step{edge: e, other: other, forward: forward, attr: m.Attribution, purpose: m.Purpose,
			vendor: m.Vendor})
	}

	return out, nil
}

// controlledFootprint collects the assets controlled by the roots along
// footprintPass. It never enters another Organization except through
// controls (subsidiary, org_unit), and never expands a Person, so a shared
// contact cannot merge two footprints.
func (w *lensWalker) controlledFootprint(roots []Asset) (map[string]Asset, []string, error) {
	owned := map[string]Asset{}
	var order, queue []string
	for _, r := range roots {
		if _, ok := owned[r.ID]; !ok {
			owned[r.ID] = r
			order = append(order, r.ID)
			queue = append(queue, r.ID)
		}
	}

	for len(queue) > 0 {
		if err := w.ctx.Err(); err != nil {
			return nil, nil, err
		}
		if w.report.Reads >= lensMaxReads {
			w.truncate("database read limit")
			break
		}

		cur := owned[queue[0]]
		queue = queue[1:]
		if cur.Type == "Person" {
			continue
		}

		steps, err := w.steps(cur)
		if err != nil {
			return nil, nil, err
		}
		for _, s := range steps {
			if _, seen := owned[s.other.ID]; seen || s.other.Type == "Person" || !footprintPass(s) ||
				(s.other.Type == "Organization" && s.attr != attrControls) {
				continue
			}
			if len(owned) >= lensMaxFootprint {
				w.truncate("controlled asset limit")
				break
			}

			owned[s.other.ID] = s.other
			order = append(order, s.other.ID)
			if w.parent != nil {
				w.parent[s.other.ID] = cur.ID
				w.via[s.other.ID] = s.edge
			}
			if w.expand == nil || w.expand[s.other.Type] {
				queue = append(queue, s.other.ID)
			}
		}
	}

	return owned, order, nil
}

// controller is the result of a controller search from one asset.
type controller struct {
	orgs    []Asset
	visited []Asset
	own     bool
}

// controllerOf searches from a toward the Organization that controls it
// along ownerPass, best first by depth plus the type distance to an
// Organization, so a netblock's registration record is read before its
// thousands of addresses. It stops at the closest Organizations, or when
// it reaches an asset in owned (then own is set).
func (w *lensWalker) controllerOf(a Asset, owned map[string]Asset) (controller, error) {
	return w.controllerSearch(a, owned, lensMaxOwnerPops)
}

// controllerSearch is controllerOf with a pop budget. Ties on depth plus
// distance go to the asset closest to an Organization, so the search
// follows one registration chain to its end before widening.
func (w *lensWalker) controllerSearch(a Asset, owned map[string]Asset, maxPops int) (controller, error) {
	if c, ok := w.controllers[a.ID]; ok {
		return c, nil
	}

	var c controller
	type item struct {
		asset Asset
		depth int
	}

	seen := map[string]bool{a.ID: true}
	frontier := []item{{asset: a}}
	best := -1
	for pops := 0; len(frontier) > 0 && pops < maxPops; pops++ {
		if err := w.ctx.Err(); err != nil {
			return c, err
		}

		next, score, dist := 0, -1, -1
		for i, it := range frontier {
			d, ok := w.ownerDist[it.asset.Type]
			if !ok {
				d = len(w.ownerDist)
			}
			if s := it.depth + d; score < 0 || s < score || (s == score && d < dist) {
				next, score, dist = i, s, d
			}
		}
		if best >= 0 && score > best {
			break
		}

		cur := frontier[next]
		frontier = append(frontier[:next], frontier[next+1:]...)
		c.visited = append(c.visited, cur.asset)
		if _, mine := owned[cur.asset.ID]; mine && cur.asset.ID != a.ID {
			c.own = true
			break
		}
		if cur.asset.Type == "Organization" {
			c.orgs = append(c.orgs, cur.asset)
			best = score
			continue
		}

		steps, err := w.steps(cur.asset)
		if err != nil {
			return c, err
		}
		for _, s := range steps {
			if seen[s.other.ID] || s.other.Type == "Person" || !ownerPass(s) {
				continue
			}
			if _, ok := w.ownerDist[s.other.Type]; !ok {
				continue
			}

			seen[s.other.ID] = true
			frontier = append(frontier, item{asset: s.other, depth: cur.depth + 1})
		}
	}

	sort.Slice(c.orgs, func(i, j int) bool { return assetLabel(c.orgs[i]) < assetLabel(c.orgs[j]) })
	w.controllers[a.ID] = c
	return c, nil
}

// owningOrganizations returns the closest Organizations documented as
// controlling root, so that a domain question also covers its registrant's
// assets. It searches breadth first along ownerPass, a level at a time up
// to lensMaxOwnerDepth, so the nearest owner is found however many
// certificates and URLs share the subject's name.
func (w *lensWalker) owningOrganizations(root Asset) ([]Asset, error) {
	if root.Type == "Organization" {
		return nil, nil
	}

	var orgs []Asset
	seen := map[string]bool{root.ID: true}
	frontier := []Asset{root}
	for depth := 0; depth < lensMaxOwnerDepth && len(frontier) > 0 && len(orgs) == 0; depth++ {
		var next []Asset
		for _, cur := range frontier {
			if err := w.ctx.Err(); err != nil {
				return nil, err
			}

			steps, err := w.steps(cur)
			if err != nil {
				return nil, err
			}
			for _, s := range steps {
				if seen[s.other.ID] || s.other.Type == "Person" || !ownerPass(s) {
					continue
				}

				seen[s.other.ID] = true
				if s.other.Type == "Organization" {
					orgs = append(orgs, s.other)
					continue
				}
				if _, ok := w.ownerDist[s.other.Type]; ok {
					next = append(next, s.other)
				}
			}
		}

		frontier = next
	}

	sort.Slice(orgs, func(i, j int) bool { return assetLabel(orgs[i]) < assetLabel(orgs[j]) })
	return orgs, nil
}
