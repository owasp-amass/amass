// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"encoding/json"
	"slices"
	"strings"
	"time"
)

// ProposalSuperseded is the status of a pending proposal a merge made moot:
// after the merge its two ends are one entity, or it asks for what an older
// pending proposal already asks. Undoing the merge makes it pending again.
const ProposalSuperseded = "superseded"

// SupersededBy is the reviewer shown on a proposal a merge superseded.
func SupersededBy(mergeID string) string {
	return "amass-ai (merge " + mergeID + ")"
}

// redirect is where a removed entity's or edge's role went, the merge (or
// restore) proposal that moved it, and when.
type redirect struct {
	to, by string
	at     time.Time
}

// Redirects map the entities and relationships that merges took out of the
// Asset Database to those that now hold what they had: a merge's survivor,
// or the entity an undone merge or removal restored under a new ID. They are
// read from the journal's merge and removal outcomes, so proposals made
// before a merge still reach the right entity.
type Redirects struct {
	entities map[string]redirect
	edges    map[string]redirect
}

// readRedirects replays the journal's merge and removal outcomes.
func readRedirects(lines []json.RawMessage) Redirects {
	r := Redirects{entities: map[string]redirect{}, edges: map[string]redirect{}}
	merges := map[string]*MergeRecord{} // applied merge proposal -> its record
	removed := map[string]string{}      // applied removal proposal -> organization
	converted := map[string]string{}    // applied conversion proposal -> person
	for _, line := range lines {
		var rec struct {
			Kind string          `json:"kind"`
			Data json.RawMessage `json:"data"`
		}
		if json.Unmarshal(line, &rec) != nil {
			continue
		}
		switch rec.Kind {
		case "duplicate_outcome":
			var o DuplicateOutcome
			if json.Unmarshal(rec.Data, &o) != nil {
				continue
			}
			switch {
			case o.Status == ProposalApplied && o.Merge != nil:
				merges[o.ProposalID] = o.Merge
				r.entities[o.Merge.DuplicateID] = redirect{to: o.Merge.SurvivorID, by: o.ProposalID, at: o.At}
				for _, e := range o.Merge.Edges {
					if e.SurvivorEdgeID != "" {
						r.edges[e.ID] = redirect{to: e.SurvivorEdgeID, by: o.ProposalID, at: o.At}
					}
				}
			case o.Status == ProposalRetracted && merges[o.ProposalID] != nil:
				m := merges[o.ProposalID]
				delete(merges, o.ProposalID)
				r.entities[m.DuplicateID] = redirect{to: o.RestoredID, by: o.ProposalID, at: o.At}
				for _, e := range m.Edges {
					delete(r.edges, e.ID)
				}
			}
		case "person_named_outcome":
			var o PersonNamedOutcome
			if json.Unmarshal(rec.Data, &o) != nil {
				continue
			}
			switch {
			case o.Status == ProposalApplied && o.Record != nil:
				removed[o.ProposalID] = o.Record.EntityID
			case o.Status == ProposalRetracted && removed[o.ProposalID] != "":
				r.entities[removed[o.ProposalID]] = redirect{to: o.RestoredID, by: o.ProposalID, at: o.At}
				delete(removed, o.ProposalID)
			}
		case "org_named_outcome":
			// a converted person's role is the organization's, until the
			// conversion is undone and the person is back
			var o OrgNamedOutcome
			if json.Unmarshal(rec.Data, &o) != nil {
				continue
			}
			switch {
			case o.Status == ProposalApplied && o.Record != nil:
				converted[o.ProposalID] = o.Record.Person.EntityID
				r.entities[o.Record.Person.EntityID] = redirect{to: o.Record.OrgID, by: o.ProposalID, at: o.At}
			case o.Status == ProposalRetracted && converted[o.ProposalID] != "":
				r.entities[converted[o.ProposalID]] = redirect{to: o.RestoredID, by: o.ProposalID, at: o.At}
				delete(converted, o.ProposalID)
			}
		}
	}
	return r
}

// resolve follows id through the redirects to the one that holds its role
// now, with the last redirect followed (zero when it was not moved).
func resolve(m map[string]redirect, id string) (string, redirect) {
	var last redirect
	for range len(m) + 1 {
		next, ok := m[id]
		if !ok || next.to == "" || next.to == id {
			break
		}
		id, last = next.to, next
	}
	return id, last
}

// Entity resolves an entity ID.
func (r Redirects) Entity(id string) string {
	to, _ := resolve(r.entities, id)
	return to
}

// Edge resolves a relationship ID.
func (r Redirects) Edge(id string) string {
	to, _ := resolve(r.edges, id)
	return to
}

// redirected resolves each entity ID in place and returns the last redirect
// it followed, zero when none was moved.
func (r Redirects) redirected(ids ...*string) redirect {
	var moved redirect
	for _, id := range ids {
		if *id == "" {
			continue
		}
		var last redirect
		if *id, last = resolve(r.entities, *id); last.by != "" {
			moved = last
		}
	}
	return moved
}

// pendingItem is a pending proposal of any kind as the supersession rule
// sees it: a key naming what it asks for once its IDs are resolved, whether
// its two ends became one entity, when it was made, and the redirect that
// moved its entities.
type pendingItem struct {
	id        string
	key       string
	collapsed bool
	created   time.Time
	moved     redirect
}

// supersede returns the pending proposals a merge made moot, each with the
// merge: those whose ends a merge made one entity, and, of the proposals
// asking for the same thing once resolved where a merge moved at least one,
// all but the oldest. Proposals no merge touched are left alone.
func supersede(items []pendingItem) map[string]redirect {
	slices.SortStableFunc(items, func(a, b pendingItem) int {
		if c := a.created.Compare(b.created); c != 0 {
			return c
		}
		return strings.Compare(a.id, b.id)
	})

	out := map[string]redirect{}
	groups := map[string][]pendingItem{}
	var keys []string
	for _, it := range items {
		if it.collapsed && it.moved.by != "" {
			out[it.id] = it.moved
			continue
		}
		if _, ok := groups[it.key]; !ok {
			keys = append(keys, it.key)
		}
		groups[it.key] = append(groups[it.key], it)
	}
	for _, k := range keys {
		g := groups[k]
		var moved redirect
		for _, it := range g {
			if it.moved.by != "" {
				moved = it.moved
				break
			}
		}
		if moved.by == "" {
			continue
		}
		for _, it := range g[1:] {
			out[it.id] = moved
		}
	}
	return out
}

// markSuperseded supersedes the pending items a merge made moot, through
// set, which is given the merge and when it was applied.
func markSuperseded(items []pendingItem, set func(id, by string, at time.Time)) {
	for id, m := range supersede(items) {
		set(id, m.by, m.at)
	}
}
