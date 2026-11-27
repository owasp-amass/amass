// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// prefetchedEdges is one asset's bounded edge read in one direction.
type prefetchedEdges struct {
	edges []graph.Relation
	more  bool
}

// footprintBatch is how many footprint assets' edges are read at a time.
const footprintBatch = 64

// prefetchFootprint reads, when id is in the footprint and its edges are not
// read yet, its edges with those of the footprint assets after it in the
// footprint's order, so a lens going through its footprint reads a batch at
// a time.
func (w *lensWalker) prefetchFootprint(id string) error {
	at, ok := w.position[id]
	if !ok {
		return nil
	}
	if _, done := w.prefetched[id+"\x00out"]; done {
		return nil
	}

	batch := []string{id}
	for _, next := range w.order[at+1:] {
		if len(batch) >= footprintBatch {
			break
		}
		if _, done := w.edges[next]; done || w.footprint[next].Type == "Person" {
			continue
		}
		if _, done := w.prefetched[next+"\x00out"]; done {
			continue
		}
		batch = append(batch, next)
	}
	return w.prefetchEdges(batch)
}

// prefetchEdges reads, when the graph can, the bounded edges of the assets
// ids not yet read in one read per direction, and the assets at their far
// ends in one batch. neighbors then uses them as its own reads.
func (w *lensWalker) prefetchEdges(ids []string) error {
	multi, ok := w.bounded.(graph.MultiEdgeReader)
	if !ok {
		return nil
	}

	var need []string
	for _, id := range ids {
		if _, done := w.edges[id]; done {
			continue
		}
		if _, done := w.prefetched[id+"\x00out"]; done {
			continue
		}

		need = append(need, id)
	}
	if len(need) < 2 {
		return nil
	}
	if w.prefetched == nil {
		w.prefetched = map[string]prefetchedEdges{}
	}

	var far []graph.Relation
	for _, dir := range []string{"out", "in"} {
		if w.outOfReads() {
			return nil // neighbors reports the read limit
		}

		w.report.Reads++
		read, more, err := multi.EdgesForAssets(w.ctx, need, dir, time.Time{}, lensMaxPerAsset)
		if err != nil {
			return err
		}

		for _, id := range need {
			w.prefetched[id+"\x00"+dir] = prefetchedEdges{edges: read[id], more: more[id]}
			far = append(far, read[id]...)
		}
	}

	var ends []string
	want := map[string]bool{}
	for _, e := range far {
		for _, id := range []string{e.FromID, e.ToID} {
			if _, known := w.assets[id]; !known && id != "" && !want[id] {
				want[id] = true
				ends = append(ends, id)
			}
		}
	}

	read, err := graph.AssetsByID(w.ctx, w.graph, ends)
	for id, a := range read {
		w.assets[id] = a
	}

	return err
}

// prefetch reads the assets at the far end of edges that are not yet known
// in one batch, when the graph can.
func (w *lensWalker) prefetch(cur graph.Asset, edges []graph.Relation) error {
	read, err := graph.FarAssets(w.ctx, w.graph, cur.ID, edges,
		func(id string) bool { _, ok := w.assets[id]; return ok })
	for id, a := range read {
		w.assets[id] = a
	}

	return err
}

// readLabel reads the edges of id with one label in one direction: every
// edge, a page at a time, when the graph can page (until the optional read
// limit), otherwise one bounded read. more reports edges left unread, and
// limit how many one read could return.
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
		if w.outOfReads() {
			w.truncate("database read limit")
			return out, false, len(out), nil
		}

		w.report.Reads++
		edges, next, err := pager.EdgesPage(w.ctx, id, dir, label, time.Time{}, cursor, lensMaxPerAsset)
		if err != nil {
			return nil, false, len(out), err
		}

		out = append(out, edges...)
		if next == "" {
			return out, false, len(out), nil
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
