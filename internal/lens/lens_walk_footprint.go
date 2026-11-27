// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

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

// footprintSteps are the steps control passes along from an asset in the
// footprint (footprintPass), compiled from the catalog: never from or to a
// Person, into an Organization only through controls, and, when the walk
// admits only some types (admitOnly), only to those.
func (w *lensWalker) footprintSteps() []graph.Step {
	if w.stepsCache != nil {
		return w.stepsCache
	}

	admits := func(t, attr string) bool {
		return t != "Person" && (t != "Organization" || attr == graph.AttrControls) &&
			(w.admitOnly == nil || w.admitOnly[t])
	}
	var out []graph.Step
	for _, r := range w.relations {
		m, ok := w.meaning(r.SourceType, r.Label, r.RelationType, r.DestinationType)
		if !ok {
			continue
		}
		if r.SourceType != "Person" && admits(r.DestinationType, m.Attribution) &&
			footprintPass(step{forward: true, attr: m.Attribution, purpose: m.Purpose}) {
			out = append(out, graph.Step{FromType: r.SourceType, Label: r.Label, RelationType: r.RelationType,
				ToType: r.DestinationType, Forward: true})
		}
		if r.DestinationType != "Person" && admits(r.SourceType, m.Attribution) &&
			footprintPass(step{forward: false, attr: m.Attribution, purpose: m.Purpose}) {
			out = append(out, graph.Step{FromType: r.SourceType, Label: r.Label, RelationType: r.RelationType,
				ToType: r.DestinationType})
		}
	}

	w.stepsCache = out
	return out
}

// footprintReserve is the share of a lens run's remaining time the
// footprint walk leaves for the lens's own reads after it.
const footprintReserve = 5

// controlledFootprint collects the assets controlled by the roots along
// footprintPass, a round at a time: each round reads, in one step read per
// batch, the edges control passes along from the assets the last round
// admitted (graph.StepsFrom), so only those edges are read. It never enters
// another Organization except through controls (subsidiary, org_unit), and
// never expands a Person, so a shared contact cannot merge two footprints.
// The walk has no size limit of its own: it stops at an optional asset or
// read limit (LensLimits), or when it has spent all but a fifth of the
// run's time, and then reports the footprint as truncated.
func (w *lensWalker) controlledFootprint(roots []graph.Asset) (map[string]graph.Asset, []string, error) {
	owned := map[string]graph.Asset{}
	w.footprint = owned
	var order, frontier []string
	admit := func(a graph.Asset, parent string, via graph.Relation) {
		owned[a.ID] = a
		order = append(order, a.ID)
		if w.parent != nil && parent != "" {
			w.parent[a.ID] = parent
			w.via[a.ID] = via
		}
		if a.Type != "Person" && (parent == "" || w.expand == nil || w.expand[a.Type]) {
			frontier = append(frontier, a.ID)
		}
	}
	for _, r := range roots {
		if _, ok := owned[r.ID]; !ok {
			w.assets[r.ID] = r
			admit(r, "", graph.Relation{})
		}
	}

	var stop time.Time
	if deadline, ok := w.ctx.Deadline(); ok {
		stop = deadline.Add(-time.Until(deadline) / footprintReserve)
	}
	steps := w.footprintSteps()
	set := graph.NewStepSet(steps)
	for len(frontier) > 0 {
		if err := w.ctx.Err(); err != nil {
			return nil, nil, err
		}
		if !stop.IsZero() && time.Now().After(stop) {
			w.truncate("time limit")
			break
		}
		if w.outOfReads() {
			w.truncate("database read limit")
			break
		}

		round := frontier
		frontier = nil
		w.report.Reads++
		edges, err := graph.StepsFrom(w.ctx, w.graph, round, steps)
		if err != nil {
			return nil, nil, err
		}
		if err := w.readAssets(edges); err != nil {
			return nil, nil, err
		}

		found, err := w.footprintCandidates(round, edges, set)
		if err != nil {
			return nil, nil, err
		}
		for _, c := range found {
			if _, seen := owned[c.asset.ID]; seen {
				continue
			}
			if w.maxAssets > 0 && len(owned) >= w.maxAssets {
				w.truncate("controlled asset limit")
				return owned, order, nil
			}
			admit(c.asset, c.parent, c.via)
		}
	}

	w.orderIndex(order)
	return owned, order, nil
}

// footprintCandidate is an asset a round found, with the asset and edge it
// was reached from.
type footprintCandidate struct {
	asset  graph.Asset
	parent string
	via    graph.Relation
}

// footprintCandidates returns, in the round's order, the assets the edges
// lead to from the round's assets that the per-asset rules admit: not
// across a shared platform's host, not into a stopAt organization, not a
// URL under a host name when hosted URLs are skipped, and not a held
// netblock's member address that hosts nothing when bare addresses are
// summarized (each counted in the report).
func (w *lensWalker) footprintCandidates(round []string, edges []graph.Relation,
	set graph.StepSet) ([]footprintCandidate, error) {
	in := make(map[string]bool, len(round))
	for _, id := range round {
		in[id] = true
	}
	byParent := map[string][]footprintCandidate{}
	queued := map[string]bool{}
	var bare []string
	bareSet := map[string]bool{}
	for _, e := range edges {
		from, to := w.assets[e.FromID], w.assets[e.ToID]
		for _, forward := range []bool{true, false} {
			cur, other := from, to
			if !forward {
				cur, other = to, from
			}
			if _, owned := w.footprint[other.ID]; owned || !in[cur.ID] || queued[other.ID] ||
				!set.Follows(e, from.Type, to.Type, forward) || platformStep(cur, step{edge: e, other: other}) ||
				w.stopAt[other.ID] {
				continue
			}
			if w.skipHostedURLs && other.Type == "URL" && cur.Type == "FQDN" {
				w.report.SkippedURLs++
				continue
			}

			queued[other.ID] = true
			byParent[cur.ID] = append(byParent[cur.ID], footprintCandidate{asset: other, parent: cur.ID, via: e})
			if w.summarizeBareAddrs && other.Type == "IPAddress" && (cur.Type == "Netblock" || cur.Type == "IPNetRecord") {
				bare = append(bare, other.ID)
				bareSet[other.ID] = true
			}
		}
	}

	hosting, err := w.addressesHosting(bare)
	if err != nil {
		return nil, err
	}
	var out []footprintCandidate
	for _, id := range round {
		// in a stable order, whatever order the store returned the edges in,
		// so a run an optional limit stops keeps the same assets
		found := byParent[id]
		sort.SliceStable(found, func(i, j int) bool {
			a, b := found[i].asset, found[j].asset
			if a.Type != b.Type {
				return a.Type < b.Type
			}
			if la, lb := graph.AssetLabel(a), graph.AssetLabel(b); la != lb {
				return la < lb
			}
			return a.ID < b.ID
		})
		for _, c := range found {
			if bareSet[c.asset.ID] && !hosting[c.asset.ID] {
				w.report.SummarizedAddresses++
				continue
			}
			out = append(out, c)
		}
	}
	return out, nil
}

// hostingTypes are what an address hosts: a name, service, URL or
// certificate on any edge.
var hostingTypes = map[string]bool{"FQDN": true, "Service": true, "URL": true, "TLSCertificate": true}

// addressesHosting reports which of the addresses host anything (an edge to
// or from a hostingTypes asset), in one step read per batch. The summarizing
// lenses keep such addresses and summarize the rest, so a held netblock's
// empty address space does not crowd the footprint. It matches on the
// neighbor's type, not footprintPass: the hosting edges (FQDN dns_record,
// port, ptr_record) are infrastructure-attributed and fail footprintPass.
func (w *lensWalker) addressesHosting(ids []string) (map[string]bool, error) {
	out := map[string]bool{}
	if len(ids) == 0 {
		return out, nil
	}

	var steps []graph.Step
	for _, r := range w.relations {
		switch {
		case r.SourceType == "IPAddress" && hostingTypes[r.DestinationType]:
			steps = append(steps, graph.Step{FromType: r.SourceType, Label: r.Label, RelationType: r.RelationType,
				ToType: r.DestinationType, Forward: true})
		case r.DestinationType == "IPAddress" && hostingTypes[r.SourceType]:
			steps = append(steps, graph.Step{FromType: r.SourceType, Label: r.Label, RelationType: r.RelationType,
				ToType: r.DestinationType})
		}
	}
	if len(steps) == 0 {
		return out, nil
	}

	w.report.Reads++
	edges, err := graph.StepsFrom(w.ctx, w.graph, ids, steps)
	if err != nil {
		return nil, err
	}
	for _, e := range edges {
		out[e.FromID], out[e.ToID] = true, true
	}
	return out, nil
}

// readAssets reads, in one batch when the graph can, the assets at the ends
// of edges that are not known yet.
func (w *lensWalker) readAssets(edges []graph.Relation) error {
	var need []string
	want := map[string]bool{}
	for _, e := range edges {
		for _, id := range []string{e.FromID, e.ToID} {
			if _, known := w.assets[id]; !known && id != "" && !want[id] {
				want[id] = true
				need = append(need, id)
			}
		}
	}

	read, err := graph.AssetsByID(w.ctx, w.graph, need)
	if err != nil {
		return err
	}
	for id, a := range read {
		w.assets[id] = a
	}
	for _, id := range need {
		if _, err := w.asset(id); err != nil {
			return err
		}
	}
	return nil
}
