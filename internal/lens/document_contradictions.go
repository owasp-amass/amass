// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// hierarchyLabels are the relations that put one organization over another.
var hierarchyLabels = []string{"org_unit", "subsidiary"}

// maxHierarchyDepth bounds the walk up a stored hierarchy.
const maxHierarchyDepth = 8

// HierarchyPredicate reports whether a document predicate puts its object
// over its subject (unit_of, subsidiary_of and the like), by the document
// signal catalog.
func HierarchyPredicate(predicate string) bool {
	for _, s := range DocumentSignals() {
		if contains(hierarchyLabels, s.Label) && contains(s.Predicates, predicate) {
			return true
		}
	}
	return false
}

// parentsOf returns the organizations stored over id by a hierarchy
// relation.
func (r *docRelations) parentsOf(id string) ([]string, error) {
	var out []string
	for _, l := range hierarchyLabels {
		edges, err := r.g.Edges(r.ctx, id, "in", l, time.Time{})
		if err != nil {
			return nil, err
		}
		for _, e := range edges {
			if e.ToID == id && e.FromID != id {
				out = append(out, e.FromID)
			}
		}
	}
	return out, nil
}

// ancestorsOf returns the organizations stored above id, within
// maxHierarchyDepth levels.
func (r *docRelations) ancestorsOf(id string) (map[string]bool, error) {
	if a, ok := r.ancestors[id]; ok {
		return a, nil
	}

	above := map[string]bool{}
	frontier := []string{id}
	for depth := 0; depth < maxHierarchyDepth && len(frontier) > 0; depth++ {
		var next []string
		for _, cur := range frontier {
			parents, err := r.parentsOf(cur)
			if err != nil {
				return nil, err
			}
			for _, p := range parents {
				if p != id && !above[p] {
					above[p] = true
					next = append(next, p)
				}
			}
		}
		frontier = next
	}

	r.ancestors[id] = above
	return above, nil
}

// contradictsStored reports whether the stored hierarchy contradicts a
// finding that puts parent over child: child is already stored above parent,
// or, for a unit, child is already stored as a unit of an organization that
// is neither above nor below parent.
func (r *docRelations) contradictsStored(parent, child graph.Asset, label string) (bool, error) {
	if !contains(hierarchyLabels, label) {
		return false, nil
	}

	above, err := r.ancestorsOf(parent.ID)
	if err != nil || above[child.ID] {
		return above[child.ID], err
	}
	if label != "org_unit" {
		return false, nil
	}

	parents, err := r.parentsOf(child.ID)
	if err != nil {
		return false, err
	}
	for _, p := range parents {
		if p == parent.ID || above[p] {
			continue
		}
		pAbove, err := r.ancestorsOf(p)
		if err != nil {
			return false, err
		}
		if !pAbove[parent.ID] {
			return true, nil
		}
	}
	return false, nil
}

// dropReversed removes the relationships the documents state both ways: two
// organizations each put over the other, by one document or two, leave
// nothing to propose.
func (r *docRelations) dropReversed() {
	for key, d := range r.found {
		if !contains(hierarchyLabels, d.signal.Label) || d.to.ID == "" {
			continue
		}
		for _, l := range hierarchyLabels {
			rev := d.to.ID + "\x00" + l + "\x00" + d.from.ID
			if _, ok := r.found[rev]; ok {
				delete(r.found, key)
				delete(r.found, rev)
			}
		}
	}
}
