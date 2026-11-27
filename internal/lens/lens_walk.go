// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Lens bounds. A lens run has no size limit of its own: it is bounded by
// its time (the context's deadline) and by the optional LensLimits.
const (
	lensMaxPerAsset = graph.MaxEdgeRead
	lensMaxExamples = 3
	// DefaultOwnerSteps is how many assets the best-first search for an
	// asset's controller visits before giving up (LensLimits.OwnerSteps).
	DefaultOwnerSteps = 100
	// DefaultOwnerDepth is how many levels the search for the subject's own
	// owner climbs (LensLimits.OwnerDepth).
	DefaultOwnerDepth = 8
)

// LensLimits optionally bound one lens run: how many controlled assets it
// follows and how many database reads it makes, where zero means no limit,
// so the run is bounded only by its time and a run a limit stops is
// reported as truncated; and how far its owner searches go, where zero
// means the default.
type LensLimits struct {
	MaxAssets int `json:"max_assets,omitempty"`
	MaxReads  int `json:"max_reads,omitempty"`
	// OwnerSteps bounds the best-first search for an asset's controller, in
	// assets visited; the search stops at the nearest organization, so the
	// bound only matters when none is near. DefaultOwnerSteps when 0.
	OwnerSteps int `json:"owner_steps,omitempty"`
	// OwnerDepth bounds the search for the subject's own owner, in levels.
	// DefaultOwnerDepth when 0.
	OwnerDepth int `json:"owner_depth,omitempty"`
}

// Validate rejects negative limits.
func (l LensLimits) Validate() error {
	if l.MaxAssets < 0 {
		return errors.New("max assets must be 0 (no limit) or more")
	}
	if l.MaxReads < 0 {
		return errors.New("max reads must be 0 (no limit) or more")
	}
	if l.OwnerSteps < 0 {
		return errors.New("owner steps must be 0 (the default) or more")
	}
	if l.OwnerDepth < 0 {
		return errors.New("owner depth must be 0 (the default) or more")
	}

	return nil
}

// withReads is l with its read limit set to reads, as a lens running others
// gives each its share.
func (l LensLimits) withReads(reads int) LensLimits {
	l.MaxReads = reads
	return l
}

// limit applies l to the walker.
func (w *lensWalker) limit(l LensLimits) {
	w.maxAssets, w.maxReads = l.MaxAssets, l.MaxReads
	w.ownerSteps, w.ownerDepth = DefaultOwnerSteps, DefaultOwnerDepth
	if l.OwnerSteps > 0 {
		w.ownerSteps = l.OwnerSteps
	}
	if l.OwnerDepth > 0 {
		w.ownerDepth = l.OwnerDepth
	}
}

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

// SharedPlatformHost reports whether a host is a shared platform where many
// unrelated parties each have a page under the one host: a code host or
// social network (semantics account_platforms.json) or a package registry's
// or documentation site (package_registries.json registry_hosts).
func SharedPlatformHost(host string) bool {
	return semantics.AccountPlatformHost(host) || semantics.PackageRegistryCatalog().RegistryHost(host)
}

// platformStep reports whether s joins a URL and its host on a shared
// platform (SharedPlatformHost). Control and ownership do not pass across
// such a step: an organization's repository or profile URL is its own, the
// platform's domain is not.
func platformStep(cur graph.Asset, s step) bool {
	switch {
	case cur.Type == "URL" && s.other.Type == "FQDN":
		return SharedPlatformHost(graph.FQDNName(s.other))
	case cur.Type == "FQDN" && s.other.Type == "URL":
		return SharedPlatformHost(graph.FQDNName(cur))
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
	// admitOnly, when set, are the only types the footprint walk admits;
	// assets of other types are not counted against its asset limit.
	admitOnly map[string]bool
	// parent and via record how each controlled asset was reached, so a
	// witnessed path can be rebuilt from the root.
	parent map[string]string
	via    map[string]graph.Relation
	// ownerDist is the type distance to an Organization along ownerPass.
	ownerDist map[string]int
	// controllers caches controllerOf results by asset ID.
	controllers map[string]controller
	// maxAssets and maxReads optionally bound this run (see LensLimits);
	// zero is no limit. ownerSteps and ownerDepth bound its owner searches.
	maxAssets  int
	maxReads   int
	ownerSteps int
	ownerDepth int
	// stepsCache holds footprintSteps once compiled.
	stepsCache []graph.Step
	// ownerStepsCache and ownerStepSet hold ownerStepList once compiled;
	// ownerEdges holds the owner-step edges read for each asset.
	ownerStepsCache []graph.Step
	ownerStepSet    graph.StepSet
	ownerEdges      map[string][]graph.Relation
	// position is each footprint asset's place in the footprint's order,
	// so reading one asset's edges reads the next ones' with it.
	position map[string]int
	order    []string
	// summarizeBareAddrs, when set, keeps an IPAddress reached through a held
	// netblock only when it hosts a name or service; the other member
	// addresses are counted in report.SummarizedAddresses rather than filling
	// the footprint. Lenses that report address space itself leave it off.
	summarizeBareAddrs bool
	// skipHostedURLs, when set, leaves out of the footprint a URL reached from
	// a host name (a page under the host, which leads only back to it) and
	// counts it in report.SkippedURLs. Lenses that never read URLs set it;
	// a URL reached from an organization (its website) is still admitted.
	skipHostedURLs bool
	// footprint is the controlled footprint once it is being collected.
	// Outside it the walker only looks for who controls an asset, so it
	// never pages through an asset's descendants (amazonaws.com's names).
	footprint map[string]graph.Asset
	// stopAt are organizations whose assets are not followed through a
	// controls edge: a group rollup scans each group organization on its
	// own, so a parent's scan leaves its subsidiaries to theirs.
	stopAt map[string]bool
	// prefetched holds bounded edge reads made for several assets at once,
	// by asset ID and direction, until neighbors uses them.
	prefetched map[string]prefetchedEdges
	// rangeBlocks caches the netblock found by range for an address.
	rangeBlocks map[string]graph.Asset
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
		ownerSteps:  DefaultOwnerSteps,
		ownerDepth:  DefaultOwnerDepth,
	}
}

// outOfReads reports whether the run has made the reads its optional read
// limit allows.
func (w *lensWalker) outOfReads() bool {
	return w.maxReads > 0 && w.report.Reads >= w.maxReads
}

// orderIndex records the footprint's order, so neighbors reads the edges of
// the footprint assets after the one asked for with it.
func (w *lensWalker) orderIndex(order []string) {
	w.order = order
	w.position = make(map[string]int, len(order))
	for i, id := range order {
		w.position[id] = i
	}
}

func (w *lensWalker) truncate(reason string) {
	truncateOnce(&w.report.Truncated, &w.report.Reason, reason)
}

// truncateOnce marks a report partial with the first reason it was cut
// short; later reasons are ignored. Every search's truncate method uses it.
func truncateOnce(truncated *bool, reason *string, why string) {
	if !*truncated {
		*truncated, *reason = true, why
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

	if err := w.prefetchFootprint(id); err != nil {
		return nil, err
	}

	var all []graph.Relation
	for _, dir := range []string{"out", "in"} {
		var edges []graph.Relation
		var more bool
		if p, ok := w.prefetched[id+"\x00"+dir]; ok {
			delete(w.prefetched, id+"\x00"+dir)
			edges, more = p.edges, p.more
		} else {
			if w.outOfReads() {
				w.truncate("database read limit")
				break
			}

			w.report.Reads++
			var err error
			edges, more, err = w.bounded.EdgesLimited(w.ctx, id, dir, "", time.Time{}, lensMaxPerAsset)
			if err != nil {
				return nil, err
			}
		}
		if more {
			// One busy relationship (an FQDN's subdomains, a netblock's
			// addresses) can fill the read; read each label on its own so
			// the others are complete.
			var err error
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
		if w.outOfReads() {
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

	if w.outOfReads() {
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
		if w.outOfReads() {
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
