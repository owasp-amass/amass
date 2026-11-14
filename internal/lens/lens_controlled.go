// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// OwnedTypes lists, from the semantics table, the asset types an owner can
// control: the valid targets of the controlled and table answers.
func OwnedTypes(schema graph.SchemaCatalog) []string {
	if schema == nil || graph.MeaningsOf(schema) == nil {
		return nil
	}

	var out []string
	for t := range graph.CatalogTypes(schema.Relations(), nil) {
		if ControlledReachable(schema, []string{t}) {
			out = append(out, t)
		}
	}

	sort.Strings(out)
	return out
}

// LensControlled asks for the assets the subject controls, optionally only
// those of the Query's target types: the netblocks, autonomous systems,
// domains and other assets attributed to an Organization by registration,
// contact and hierarchy relationships. Like the third-party lens it is
// answered in Go from the reviewed attribution table.
const LensControlled = "controlled"

// ControlledReport is the result of the controlled-assets lens.
type ControlledReport struct {
	Root           graph.Asset       `json:"root"`
	Owners         []string          `json:"owners,omitempty"`
	TargetTypes    []string          `json:"target_types,omitempty"`
	Footprint      int               `json:"footprint"`
	FootprintTypes map[string]int    `json:"footprint_types"`
	Matches        []graph.PlanMatch `json:"matches"`
	Reads          int               `json:"reads"`
	Truncated      bool              `json:"truncated"`
	Reason         string            `json:"reason,omitempty"`
}

// footprintExpansionTypes returns the asset types from which a controlled
// walk can still reach one of targets, from the semantics table, so the
// walk need not read assets (such as hundreds of URLs) that cannot lead to
// an answer.
func footprintExpansionTypes(relations []graph.RelationshipSchema, meaning graph.MeaningFunc, targets []string) map[string]bool {
	moves := typeMoves(relations, meaning, footprintPass)
	expand := map[string]bool{}
	for _, t := range targets {
		for kind, d := range distanceTo(moves, t) {
			if d > 0 && kind != "Person" {
				expand[kind] = true
			}
		}
	}

	return expand
}

// ControlledReachable reports whether a controlled walk from an
// Organization can reach every target type.
func ControlledReachable(schema graph.SchemaCatalog, targets []string) bool {
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil || len(targets) == 0 {
		return false
	}
	for _, t := range targets {
		if t == "Organization" || t == "Person" ||
			!footprintExpansionTypes(schema.Relations(), meaning, []string{t})["Organization"] {
			return false
		}
	}

	return true
}

// path rebuilds the witnessed path from a walk root to id.
func (w *lensWalker) path(id string, owned map[string]graph.Asset) graph.PlanMatch {
	var nodes []graph.Asset
	var edges []graph.Relation
	for cur := id; ; {
		nodes = append([]graph.Asset{owned[cur]}, nodes...)
		p, ok := w.parent[cur]
		if !ok {
			break
		}

		edges = append([]graph.Relation{w.via[cur]}, edges...)
		cur = p
	}

	m := graph.PlanMatch{Nodes: nodes, Edges: edges}
	m.PathID = graph.WitnessPathID(m)
	return m
}

// SearchControlled runs the controlled-assets lens from root.
func SearchControlled(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, root graph.Asset, targets []string, limit int) (ControlledReport, error) {
	report := ControlledReport{Root: root, TargetTypes: targets, FootprintTypes: map[string]int{},
		Matches: []graph.PlanMatch{}}
	meaning := graph.MeaningsOf(schema)
	if schema == nil || meaning == nil {
		return report, errors.New("the controlled lens requires relationship semantics")
	}

	bounded, ok := g.(graph.BoundedGraph)
	if !ok {
		return report, errors.New("bounded graph reader required")
	}

	counters := &ThirdPartyReport{}
	w := newLensWalker(ctx, g, bounded, meaning, schema.Relations(), root, counters)
	w.parent, w.via = map[string]string{}, map[string]graph.Relation{}
	if len(targets) > 0 {
		w.expand = footprintExpansionTypes(w.relations, meaning, targets)
	}

	roots := []graph.Asset{root}
	owners, err := w.owningOrganizations(root)
	if err != nil {
		return report, err
	}
	for _, o := range owners {
		report.Owners = append(report.Owners, graph.AssetLabel(o))
		roots = append(roots, o)
	}

	owned, order, err := w.controlledFootprint(roots)
	if err != nil {
		return report, err
	}

	want := map[string]bool{}
	for _, t := range targets {
		want[t] = true
	}

	report.Footprint = len(owned)
	for _, id := range order {
		a := owned[id]
		report.FootprintTypes[a.Type]++
		if id == root.ID || (len(want) > 0 && !want[a.Type]) {
			continue
		}
		if len(report.Matches) >= limit {
			counters.Truncated, counters.Reason = true, "match limit"
			break
		}

		report.Matches = append(report.Matches, w.path(id, owned))
	}

	report.Reads, report.Truncated, report.Reason = counters.Reads, counters.Truncated, counters.Reason
	sort.SliceStable(report.Matches, func(i, j int) bool {
		a := report.Matches[i].Nodes[len(report.Matches[i].Nodes)-1]
		b := report.Matches[j].Nodes[len(report.Matches[j].Nodes)-1]
		if a.Type != b.Type {
			return a.Type < b.Type
		}

		return graph.AssetLabel(a) < graph.AssetLabel(b)
	})
	return report, nil
}

// WitnessChain renders a path as "a --label--> b <--label-- c".
func WitnessChain(p graph.PlanMatch) string {
	var b strings.Builder
	for i, n := range p.Nodes {
		if i > 0 {
			e := p.Edges[i-1]
			if e.FromID == p.Nodes[i-1].ID {
				fmt.Fprintf(&b, " --%s--> ", e.Label)
			} else {
				fmt.Fprintf(&b, " <--%s-- ", e.Label)
			}
		}

		fmt.Fprintf(&b, "%s %s", n.Type, graph.AssetLabel(n))
	}

	return b.String()
}

// ControlledAnswer renders a ControlledReport as plain text.
func ControlledAnswer(r ControlledReport) string {
	subject := graph.AssetLabel(r.Root) + " (" + r.Root.Type + ")"
	what := "asset(s)"
	if len(r.TargetTypes) > 0 {
		what = strings.Join(r.TargetTypes, " or ") + " asset(s)"
	}

	var b strings.Builder
	switch {
	case r.Footprint <= 1:
		fmt.Fprintf(&b, "No assets are documented as controlled by %s: the Asset Database has no registrant, "+
			"contact, website or subsidiary relationships that attribute assets to it.", subject)
		return b.String()
	case len(r.Matches) == 0:
		types := make([]string, 0, len(r.FootprintTypes))
		for t, n := range r.FootprintTypes {
			types = append(types, fmt.Sprintf("%d %s", n, t))
		}

		sort.Strings(types)
		fmt.Fprintf(&b, "No %s are documented as controlled by %s. The assets attributed to it are: %s.", what,
			subject, strings.Join(types, ", "))
	default:
		fmt.Fprintf(&b, "Found %d %s controlled by %s", len(r.Matches), what, subject)
		if len(r.Owners) > 0 {
			fmt.Fprintf(&b, " or its registrant %s", strings.Join(r.Owners, ", "))
		}

		b.WriteString(":\n")
		for _, m := range r.Matches {
			last := m.Nodes[len(m.Nodes)-1]
			fmt.Fprintf(&b, "  %s (%s), via %s\n", graph.AssetLabel(last), last.Type, WitnessChain(m))
		}

		b.WriteString("Control is attributed from stored registration, contact and hierarchy relationships; it " +
			"is not verified legal ownership.")
	}
	if r.Truncated {
		b.WriteString(" Results are partial (" + r.Reason + "); additional assets may exist.")
	}

	return b.String()
}
