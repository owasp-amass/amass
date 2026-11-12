// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
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

// lensMaxPerLabel bounds how many edges with one label a lens reads from
// one asset, a page at a time, when one read is not enough. It is a
// variable so tests can lower it.
var lensMaxPerLabel = 10 * MaxEdgeRead

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
			// One busy relationship (an FQDN's subdomains, a netblock's
			// addresses) can fill the read; read each label on its own so
			// the others are complete.
			if edges, err = w.neighborsByLabel(id, dir); err != nil {
				return nil, err
			}
		}

		all = append(all, edges...)
	}

	w.edges[id] = all
	return all, nil
}

// neighborsByLabel reads the edges of id in one direction label by label,
// for the labels the schema allows there and the semantics table gives a
// meaning. A label that alone has more than lensMaxPerAsset edges is still
// partial, and the report names it.
func (w *lensWalker) neighborsByLabel(id, dir string) ([]Relation, error) {
	a := w.assets[id]
	seen := map[string]bool{}
	var out []Relation
	for _, label := range w.labelsFor(a.Type, dir) {
		if w.report.Reads >= lensMaxReads {
			w.truncate("database read limit")
			break
		}

		edges, more, limit, err := w.readLabel(id, dir, label)
		if err != nil {
			return nil, err
		}
		if more {
			w.truncate(fmt.Sprintf("more than %d %s %s edges on %s %s", limit, dir, label, a.Type, assetLabel(a)))
		}
		for _, e := range edges {
			if !seen[e.ID] {
				seen[e.ID] = true
				out = append(out, e)
			}
		}
	}

	return out, nil
}

// readLabel reads the edges of id with one label in one direction. When the
// graph can page, it reads up to lensMaxPerLabel edges a page at a time;
// otherwise one bounded read. more reports edges left unread, beyond cap.
func (w *lensWalker) readLabel(id, dir, label string) ([]Relation, bool, int, error) {
	pager, ok := w.graph.(PagedGraph)
	if !ok {
		w.report.Reads++
		edges, more, err := w.bounded.EdgesLimited(w.ctx, id, dir, label, time.Time{}, lensMaxPerAsset)
		return edges, more, lensMaxPerAsset, err
	}

	var out []Relation
	cursor := ""
	for {
		if w.report.Reads >= lensMaxReads {
			w.truncate("database read limit")
			return out, false, lensMaxPerLabel, nil
		}

		w.report.Reads++
		edges, next, err := pager.EdgesPage(w.ctx, id, dir, label, time.Time{}, cursor,
			min(lensMaxPerAsset, lensMaxPerLabel-len(out)))
		if err != nil {
			return nil, false, lensMaxPerLabel, err
		}

		out = append(out, edges...)
		if next == "" {
			return out, false, lensMaxPerLabel, nil
		}
		if len(out) >= lensMaxPerLabel {
			return out, true, lensMaxPerLabel, nil
		}
		cursor = next
	}
}

// labelsFor returns the relationship labels the schema allows for an asset
// type in one direction that the semantics table gives a meaning, sorted.
func (w *lensWalker) labelsFor(kind, dir string) []string {
	set := map[string]bool{}
	for _, r := range w.relations {
		if (dir == "out" && r.SourceType != kind) || (dir == "in" && r.DestinationType != kind) {
			continue
		}
		if _, ok := w.meaning(r.SourceType, r.Label, r.RelationType, r.DestinationType); ok {
			set[r.Label] = true
		}
	}

	out := make([]string, 0, len(set))
	for l := range set {
		out = append(out, l)
	}
	sort.Strings(out)
	return out
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

// WitnessEdge is one stored relationship that supports an answer, with
// the labels of its two assets.
type WitnessEdge struct {
	EdgeID       string `json:"edge_id"`
	Label        string `json:"label"`
	RelationType string `json:"relation_type"`
	FromID       string `json:"from_id"`
	FromType     string `json:"from_type"`
	From         string `json:"from"`
	ToID         string `json:"to_id"`
	ToType       string `json:"to_type"`
	To           string `json:"to"`
	// Detail summarizes the stored relation's own fields, such as
	// "443/tcp" for a port relation.
	Detail string `json:"detail,omitempty"`
}

// witnessOf orients a stored edge between a and b as it is stored.
func witnessOf(e Relation, a, b Asset) WitnessEdge {
	from, to := a, b
	if e.FromID == b.ID {
		from, to = b, a
	}

	return WitnessEdge{EdgeID: e.ID, Label: e.Label, RelationType: e.Type, FromID: from.ID, FromType: from.Type,
		From: assetLabel(from), ToID: to.ID, ToType: to.Type, To: assetLabel(to), Detail: relationDetail(e)}
}

// relationDetail summarizes the fields a stored relation carries beyond
// its label, such as a port number and protocol ("443/tcp").
func relationDetail(e Relation) string {
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

// pathWitness returns the edges of a witnessed path.
func pathWitness(p PlanMatch) []WitnessEdge {
	out := make([]WitnessEdge, 0, len(p.Edges))
	for i, e := range p.Edges {
		if i+1 < len(p.Nodes) {
			out = append(out, witnessOf(e, p.Nodes[i], p.Nodes[i+1]))
		}
	}

	return out
}

// link records how a search reached an asset.
type link struct {
	parent Asset
	edge   Relation
}

// controller is the result of a controller search from one asset.
type controller struct {
	orgs    []Asset
	visited []Asset
	own     bool
	links   map[string]link
}

// witness returns the edges from the search's start to id.
func (c controller) witness(id string, assets map[string]Asset) []WitnessEdge {
	var out []WitnessEdge
	for cur := id; ; {
		l, ok := c.links[cur]
		if !ok {
			break
		}

		out = append([]WitnessEdge{witnessOf(l.edge, l.parent, assets[cur])}, out...)
		cur = l.parent.ID
	}

	return out
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

	c := controller{links: map[string]link{}}
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
			c.links[s.other.ID] = link{parent: cur.asset, edge: s.edge}
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
