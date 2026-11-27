// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// FootprintGraph turns the controlled-assets lens's witness paths into viz
// nodes and edges: every asset the subject controls, each joined to the
// subject by the relations that put it in the footprint.
func FootprintGraph(r lens.ControlledReport) ([]Node, []Edge) {
	var nodes []Node
	var edges []Edge
	index := map[string]int{}
	seen := map[[3]string]bool{}
	node := func(a graph.Asset) int {
		if i, ok := index[a.ID]; ok {
			return i
		}

		i := len(nodes)
		index[a.ID] = i
		label := strings.ReplaceAll(graph.AssetLabel(a), "\"", "")
		nodes = append(nodes, Node{ID: i, Type: a.Type, Label: label, Title: a.Type + ": " + label})
		return i
	}

	if r.Root.ID != "" {
		node(r.Root)
	}
	for _, m := range r.Matches {
		for _, a := range m.Nodes {
			node(a)
		}
		for _, e := range m.Edges {
			key := [3]string{e.FromID, e.Label, e.ToID}
			from, ok1 := index[e.FromID]
			to, ok2 := index[e.ToID]
			if seen[key] || !ok1 || !ok2 {
				continue
			}

			seen[key] = true
			edges = append(edges, Edge{From: from, To: to, Label: e.Label, Title: e.Label})
		}
	}

	return nodes, edges
}

// MermaidSummary draws a graph by asset type: one box per type with how
// many assets it holds, and one arrow per relation between types with how
// many relations it stands for. It stays readable at any size.
func MermaidSummary(nodes []Node, edges []Edge) string {
	counts := map[string]int{}
	for _, n := range nodes {
		counts[n.Type]++
	}

	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}

	sort.Strings(types)

	id := map[string]string{}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for i, t := range types {
		id[t] = fmt.Sprintf("t%d", i)
		fmt.Fprintf(&b, "  %s[\"%s (%d)\"]\n", id[t], safe(t), counts[t])
	}

	type link struct{ from, label, to string }
	links := map[link]int{}
	for _, e := range edges {
		if e.From < 0 || e.From >= len(nodes) || e.To < 0 || e.To >= len(nodes) {
			continue
		}

		links[link{nodes[e.From].Type, e.Label, nodes[e.To].Type}]++
	}

	keys := make([]link, 0, len(links))
	for k := range links {
		keys = append(keys, k)
	}

	sort.Slice(keys, func(i, j int) bool {
		if links[keys[i]] != links[keys[j]] {
			return links[keys[i]] > links[keys[j]]
		}

		return fmt.Sprint(keys[i]) < fmt.Sprint(keys[j])
	})
	for _, k := range keys {
		fmt.Fprintf(&b, "  %s -->|\"%s (%d)\"| %s\n", id[k.from], safe(k.label), links[k], id[k.to])
	}

	return b.String()
}

// MermaidDetail draws every node and edge, for graphs small enough to read;
// it returns "" for larger ones.
func MermaidDetail(nodes []Node, edges []Edge, maxNodes int) string {
	if len(nodes) == 0 || len(nodes) > maxNodes {
		return ""
	}

	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for _, n := range nodes {
		fmt.Fprintf(&b, "  n%d[\"%s: %s\"]\n", n.ID, safe(n.Type), safe(n.Label))
	}
	for _, e := range edges {
		fmt.Fprintf(&b, "  n%d -->|\"%s\"| n%d\n", e.From, safe(e.Label), e.To)
	}

	return b.String()
}

// safe keeps text that cannot break out of a Mermaid label.
func safe(s string) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() > 96 {
			break
		}
		if unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("-_ .:/@,()", r) {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "unknown"
	}

	return b.String()
}
