// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Lens bounds. Lens walks never send assets to a model, so these are
// database-cost limits rather than context limits.
const (
	lensMaxFootprint = 2000
	lensMaxPerAsset  = graph.MaxEdgeRead
	lensMaxReads     = 20000
	// LensMaxAssetsLimit and LensMaxReadsLimit bound what a caller may ask
	// for in LensLimits.
	LensMaxAssetsLimit = 100000
	LensMaxReadsLimit  = 1000000
	lensMaxExamples    = 3
	// lensMaxOwnerPops bounds the controller search from one asset.
	lensMaxOwnerPops = 40
	// lensMaxOwnerDepth bounds the search for the subject's own owner.
	lensMaxOwnerDepth = 5
)

// LensLimits bound one lens run: how many controlled assets it follows and
// how many database reads it makes. Zero means the default (2,000 assets
// and 20,000 reads).
type LensLimits struct {
	MaxAssets int `json:"max_assets,omitempty"`
	MaxReads  int `json:"max_reads,omitempty"`
}

// Validate rejects limits outside what a lens run allows.
func (l LensLimits) Validate() error {
	if l.MaxAssets < 0 || l.MaxAssets > LensMaxAssetsLimit {
		return fmt.Errorf("max assets must be 1..%d", LensMaxAssetsLimit)
	}
	if l.MaxReads < 0 || l.MaxReads > LensMaxReadsLimit {
		return fmt.Errorf("max reads must be 1..%d", LensMaxReadsLimit)
	}

	return nil
}

func (l LensLimits) assets() int {
	if l.MaxAssets > 0 {
		return l.MaxAssets
	}

	return lensMaxFootprint
}

func (l LensLimits) reads() int {
	if l.MaxReads > 0 {
		return l.MaxReads
	}

	return lensMaxReads
}

// LensMaxPerLabel bounds how many edges with one label a lens reads from
// one asset, a page at a time, when one read is not enough. It is a
// variable so tests can lower it.
var LensMaxPerLabel = 10 * graph.MaxEdgeRead

// purposeHierarchy marks same_subject edges that link a parent to a child
// (the FQDN node hierarchy). Control descends them; ownership ascends them.
const purposeHierarchy = "hierarchy"

// footprintPass reports whether control passes from the expanded asset to
// the other end of s: same_subject edges (hierarchy edges only downward),
// controls edges forward and controller edges backward.
func footprintPass(s step) bool {
	switch s.attr {
	case graph.AttrSameSubject:
		return s.purpose != purposeHierarchy || s.forward
	case graph.AttrControls:
		return s.forward
	case graph.AttrController:
		return !s.forward
	}

	return false
}

// ownerPass reports whether s moves toward the party that controls the
// expanded asset: same_subject edges (hierarchy edges only upward),
// controller edges forward and controls edges backward.
func ownerPass(s step) bool {
	switch s.attr {
	case graph.AttrSameSubject:
		return s.purpose != purposeHierarchy || !s.forward
	case graph.AttrController:
		return s.forward
	case graph.AttrControls:
		return !s.forward
	}

	return false
}

// typeMoves builds the type-level graph of a pass rule from the catalog.
// pass is called with a synthetic step for each direction of each
// transition.
func typeMoves(relations []graph.RelationshipSchema, meaning graph.MeaningFunc, pass func(step) bool) map[string]map[string]bool {
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
	graph     graph.Graph
	bounded   graph.BoundedGraph
	meaning   graph.MeaningFunc
	relations []graph.RelationshipSchema
	assets    map[string]graph.Asset
	edges     map[string][]graph.Relation
	report    *ThirdPartyReport
	// expand, when set, limits which controlled asset types are expanded
	// further; other controlled assets are recorded but not read.
	expand map[string]bool
	// parent and via record how each controlled asset was reached, so a
	// witnessed path can be rebuilt from the root.
	parent map[string]string
	via    map[string]graph.Relation
	// ownerDist is the type distance to an Organization along ownerPass.
	ownerDist map[string]int
	// controllers caches controllerOf results by asset ID.
	controllers map[string]controller
	// maxAssets and maxReads bound this run (see LensLimits).
	maxAssets int
	maxReads  int
	// footprint is the controlled footprint once it is being collected.
	// Outside it the walker only looks for who controls an asset, so it
	// never pages through an asset's descendants (amazonaws.com's names).
	footprint map[string]graph.Asset
	// stopAt are organizations whose assets are not followed through a
	// controls edge: a group rollup scans each group organization on its
	// own, so a parent's scan leaves its subsidiaries to theirs.
	stopAt map[string]bool
}

func newLensWalker(ctx context.Context, g graph.Graph, bounded graph.BoundedGraph, meaning graph.MeaningFunc, relations []graph.RelationshipSchema, root graph.Asset, report *ThirdPartyReport) *lensWalker {
	return &lensWalker{
		ctx:         ctx,
		graph:       g,
		bounded:     bounded,
		meaning:     meaning,
		relations:   relations,
		assets:      map[string]graph.Asset{root.ID: root},
		edges:       map[string][]graph.Relation{},
		report:      report,
		ownerDist:   distanceTo(typeMoves(relations, meaning, ownerPass), "Organization"),
		controllers: map[string]controller{},
		maxAssets:   lensMaxFootprint,
		maxReads:    lensMaxReads,
	}
}

func (w *lensWalker) truncate(reason string) {
	if !w.report.Truncated {
		w.report.Truncated = true
		w.report.Reason = reason
	}
}

func (w *lensWalker) asset(id string) (graph.Asset, error) {
	if a, ok := w.assets[id]; ok {
		return a, nil
	}

	a, err := w.graph.GetAsset(w.ctx, id)
	if err != nil {
		return graph.Asset{}, err
	}

	w.assets[id] = a
	return a, nil
}

// neighbors returns the stored edges in both directions for id, read once.
func (w *lensWalker) neighbors(id string) ([]graph.Relation, error) {
	if e, ok := w.edges[id]; ok {
		return e, nil
	}

	var all []graph.Relation
	for _, dir := range []string{"out", "in"} {
		if w.report.Reads >= w.maxReads {
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
func (w *lensWalker) neighborsByLabel(id, dir string) ([]graph.Relation, error) {
	a := w.assets[id]
	labels := w.labelsFor(a.Type, dir)
	if _, mine := w.footprint[id]; dir == "out" && w.footprint != nil && !mine {
		labels = w.withoutDescent(a.Type, labels)
	}

	if lr, ok := w.bounded.(graph.LabeledEdgeReader); ok && len(labels) > 0 {
		return w.neighborsPerLabel(lr, a, dir, labels)
	}

	seen := map[string]bool{}
	var out []graph.Relation
	for _, label := range labels {
		if w.report.Reads >= w.maxReads {
			w.truncate("database read limit")
			break
		}

		edges, more, limit, err := w.readLabel(id, dir, label)
		if err != nil {
			return nil, err
		}
		if more {
			w.truncate(fmt.Sprintf("more than %d %s %s edges on %s %s", limit, dir, label, a.Type, graph.AssetLabel(a)))
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

// neighborsPerLabel is neighborsByLabel with one read of every label's first
// edges; only a label with more is then read on its own, a page at a time.
func (w *lensWalker) neighborsPerLabel(lr graph.LabeledEdgeReader, a graph.Asset, dir string,
	labels []string) ([]graph.Relation, error) {
	seen := map[string]bool{}
	var out []graph.Relation
	add := func(edges []graph.Relation) {
		for _, e := range edges {
			if !seen[e.ID] {
				seen[e.ID] = true
				out = append(out, e)
			}
		}
	}

	if w.report.Reads >= w.maxReads {
		w.truncate("database read limit")
		return out, nil
	}
	w.report.Reads++
	edges, more, err := lr.EdgesPerLabel(w.ctx, a.ID, dir, labels, time.Time{}, lensMaxPerAsset)
	if err != nil {
		return nil, err
	}
	add(edges)

	_, pages := w.graph.(graph.PagedGraph)
	for _, label := range more {
		if !pages {
			w.truncate(fmt.Sprintf("more than %d %s %s edges on %s %s", lensMaxPerAsset, dir, label, a.Type,
				graph.AssetLabel(a)))
			continue
		}
		if w.report.Reads >= w.maxReads {
			w.truncate("database read limit")
			break
		}
		edges, m, limit, err := w.readLabel(a.ID, dir, label)
		if err != nil {
			return nil, err
		}
		if m {
			w.truncate(fmt.Sprintf("more than %d %s %s edges on %s %s", limit, dir, label, a.Type, graph.AssetLabel(a)))
		}
		add(edges)
	}
	return out, nil
}

// prefetch reads the assets at the far end of edges that are not yet known
// in one batch, when the graph can.
func (w *lensWalker) prefetch(cur graph.Asset, edges []graph.Relation) error {
	batch, ok := w.graph.(graph.AssetBatchReader)
	if !ok {
		return nil
	}
	var ids []string
	want := map[string]bool{}
	for _, e := range edges {
		other := e.ToID
		if e.FromID != cur.ID {
			other = e.FromID
		}
		if _, known := w.assets[other]; !known && other != "" && other != cur.ID && !want[other] {
			want[other] = true
			ids = append(ids, other)
		}
	}
	if len(ids) < 2 {
		return nil
	}
	found, err := batch.GetAssets(w.ctx, ids)
	if err != nil {
		return err
	}
	for id, a := range found {
		w.assets[id] = a
	}
	return nil
}

// readLabel reads the edges of id with one label in one direction. When the
// graph can page, it reads up to lensMaxPerLabel edges a page at a time;
// otherwise one bounded read. more reports edges left unread, beyond cap.
func (w *lensWalker) readLabel(id, dir, label string) ([]graph.Relation, bool, int, error) {
	pager, ok := w.graph.(graph.PagedGraph)
	if !ok {
		w.report.Reads++
		edges, more, err := w.bounded.EdgesLimited(w.ctx, id, dir, label, time.Time{}, lensMaxPerAsset)
		return edges, more, lensMaxPerAsset, err
	}

	var out []graph.Relation
	cursor := ""
	for {
		if w.report.Reads >= w.maxReads {
			w.truncate("database read limit")
			return out, false, LensMaxPerLabel, nil
		}

		w.report.Reads++
		edges, next, err := pager.EdgesPage(w.ctx, id, dir, label, time.Time{}, cursor,
			min(lensMaxPerAsset, LensMaxPerLabel-len(out)))
		if err != nil {
			return nil, false, LensMaxPerLabel, err
		}

		out = append(out, edges...)
		if next == "" {
			return out, false, LensMaxPerLabel, nil
		}
		if len(out) >= LensMaxPerLabel {
			return out, true, LensMaxPerLabel, nil
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

// withoutDescent drops the outgoing labels that only lead down a hierarchy
// from an asset type (an FQDN's node children): the search for an asset's
// controller moves up a hierarchy, never down.
func (w *lensWalker) withoutDescent(kind string, labels []string) []string {
	descent := map[string]bool{}
	other := map[string]bool{}
	for _, r := range w.relations {
		if r.SourceType != kind {
			continue
		}
		m, ok := w.meaning(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if !ok {
			continue
		}
		if m.Attribution == graph.AttrSameSubject && m.Purpose == purposeHierarchy {
			descent[r.Label] = true
		} else {
			other[r.Label] = true
		}
	}

	out := make([]string, 0, len(labels))
	for _, l := range labels {
		if !descent[l] || other[l] {
			out = append(out, l)
		}
	}
	return out
}

// step is one stored edge seen from the asset being expanded, with its
// semantics.
type step struct {
	edge    graph.Relation
	other   graph.Asset
	forward bool
	attr    string
	purpose string
	vendor  bool
}

func (w *lensWalker) steps(cur graph.Asset) ([]step, error) {
	edges, err := w.neighbors(cur.ID)
	if err != nil {
		return nil, err
	}

	if err := w.prefetch(cur, edges); err != nil {
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
func (w *lensWalker) controlledFootprint(roots []graph.Asset) (map[string]graph.Asset, []string, error) {
	owned := map[string]graph.Asset{}
	w.footprint = owned
	var order, queue, deferred []string
	last := followLast()
	admit := func(a graph.Asset, parent string, via graph.Relation) {
		owned[a.ID] = a
		order = append(order, a.ID)
		if w.parent != nil && parent != "" {
			w.parent[a.ID] = parent
			w.via[a.ID] = via
		}
		switch {
		case parent != "" && w.expand != nil && !w.expand[a.Type]:
		case parent != "" && last[a.Type]:
			// follow_last assets count in their turn but are followed only
			// once nothing else is left to follow.
			deferred = append(deferred, a.ID)
		default:
			queue = append(queue, a.ID)
		}
	}
	for _, r := range roots {
		if _, ok := owned[r.ID]; !ok {
			admit(r, "", graph.Relation{})
		}
	}

	// Assets found but not yet admitted wait by type, and the asset limit is
	// shared out a type at a time in turn, so a footprint larger than the
	// limit is a sample of every kind of asset (names, addresses, URLs,
	// services, certificates) rather than the first thousands of subdomains
	// found. Assets of the follow_last types take their turn too, but are
	// followed only when nothing else is left, so they spend few reads.
	type waiting struct {
		asset  graph.Asset
		parent string
		via    graph.Relation
	}
	pending := map[string][]waiting{}
	var kinds []string // types in the order first found, for a stable turn order
	queued := map[string]bool{}
	turn := 0
	next := func() (waiting, bool) {
		for range kinds {
			t := kinds[turn%len(kinds)]
			turn++
			for len(pending[t]) > 0 {
				c := pending[t][0]
				pending[t] = pending[t][1:]
				if _, seen := owned[c.asset.ID]; !seen {
					return c, true
				}
			}
		}
		return waiting{}, false
	}

	for {
		if err := w.ctx.Err(); err != nil {
			return nil, nil, err
		}
		if len(queue) == 0 {
			c, ok := next()
			if !ok {
				if len(deferred) == 0 {
					break
				}
				queue, deferred = deferred, nil
				continue
			}
			if len(owned) >= w.maxAssets {
				w.truncate("controlled asset limit")
				break
			}
			admit(c.asset, c.parent, c.via)
			continue
		}
		if w.report.Reads >= w.maxReads {
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
			if _, seen := owned[s.other.ID]; seen || queued[s.other.ID] || s.other.Type == "Person" ||
				!footprintPass(s) ||
				(s.other.Type == "Organization" && (s.attr != graph.AttrControls || w.stopAt[s.other.ID])) {
				continue
			}
			queued[s.other.ID] = true
			if _, known := pending[s.other.Type]; !known {
				kinds = append(kinds, s.other.Type)
			}
			pending[s.other.Type] = append(pending[s.other.Type], waiting{asset: s.other, parent: cur.ID, via: s.edge})
		}
	}

	return owned, order, nil
}

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
}

// controller is the result of a controller search from one asset.
type controller struct {
	orgs    []graph.Asset
	visited []graph.Asset
	own     bool
	links   map[string]link
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
// along ownerPass, best first by depth plus the type distance to an
// Organization, so a netblock's registration record is read before its
// thousands of addresses. It stops at the closest Organizations, or when
// it reaches an asset in owned (then own is set).
func (w *lensWalker) controllerOf(a graph.Asset, owned map[string]graph.Asset) (controller, error) {
	return w.controllerSearch(a, owned, lensMaxOwnerPops)
}

// controllerSearch is controllerOf with a pop budget. Ties on depth plus
// distance go to the asset closest to an Organization, so the search
// follows one registration chain to its end before widening.
func (w *lensWalker) controllerSearch(a graph.Asset, owned map[string]graph.Asset, maxPops int) (controller, error) {
	if c, ok := w.controllers[a.ID]; ok {
		return c, nil
	}

	c := controller{links: map[string]link{}}
	type item struct {
		asset graph.Asset
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

	sort.Slice(c.orgs, func(i, j int) bool { return graph.AssetLabel(c.orgs[i]) < graph.AssetLabel(c.orgs[j]) })
	w.controllers[a.ID] = c
	return c, nil
}

// owningOrganizations returns the closest Organizations documented as
// controlling root, so that a domain question also covers its registrant's
// assets. It searches breadth first along ownerPass, a level at a time up
// to lensMaxOwnerDepth, so the nearest owner is found however many
// certificates and URLs share the subject's name.
func (w *lensWalker) owningOrganizations(root graph.Asset) ([]graph.Asset, error) {
	if root.Type == "Organization" {
		return nil, nil
	}

	var orgs []graph.Asset
	seen := map[string]bool{root.ID: true}
	frontier := []graph.Asset{root}
	for depth := 0; depth < lensMaxOwnerDepth && len(frontier) > 0 && len(orgs) == 0; depth++ {
		var next []graph.Asset
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

	sort.Slice(orgs, func(i, j int) bool { return graph.AssetLabel(orgs[i]) < graph.AssetLabel(orgs[j]) })
	return orgs, nil
}
