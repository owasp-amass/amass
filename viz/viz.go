// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
	"context"
	"strings"

	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/cayleygraph/quad"
)

// Edge represents an Amass graph edge throughout the viz package.
type Edge struct {
	From, To int
	Label    string
	Title    string
}

// Node represents an Amass graph node throughout the viz package.
type Node struct {
	ID         int
	Type       string
	Label      string
	Title      string
	Source     string
	ActualType string
}

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func VizData(ctx context.Context, g *netmap.Graph, uuids []string) ([]Node, []Edge) {
	quads, err := g.ReadEventQuads(ctx, uuids...)
	if err != nil {
		return nil, nil
	}

	nodeQuads := make(map[string][]quad.Quad)
	for _, q := range quads {
		if k := valToStr(q.Get(quad.Subject)); k != "" {
			nodeQuads[k] = append(nodeQuads[k], q)
		}
	}

	var idx int
	var nodes []Node
	nodeToIdx := make(map[string]int)
	for subject, qs := range nodeQuads {
		ntype := getType(qs)
		if ntype == "" || ntype == "source" || ntype == "event" || ntype == "response" {
			continue
		}
		if ntype == "fqdn" && isTLD(subject, nodeQuads) {
			continue
		}

		src := getSource(subject, uuids, nodeQuads)
		if src == "" {
			continue
		}

		newtype := convertNodeType(subject, ntype, nodeQuads)
		if newtype == "" {
			continue
		}

		title := newtype + ": " + subject
		if newtype == "as" {
			title = title + ", Desc: " + getASDesc(qs)
		}

		n := Node{
			Type:       newtype,
			Label:      subject,
			Title:      title,
			Source:     src,
			ActualType: ntype,
		}

		n.ID = idx
		// Keep track of which indices nodes were assigned to
		nodeToIdx[subject] = idx
		idx++
		nodes = append(nodes, n)
	}

	return nodes, vizEdges(nodes, nodeToIdx, nodeQuads)
}

func getType(quads []quad.Quad) string {
	var t string

	for _, q := range quads {
		if p := valToStr(q.Get(quad.Predicate)); p == "type" {
			if obj := valToStr(q.Get(quad.Object)); obj != "" {
				t = obj
			}
			break
		}
	}

	return t
}

func getASDesc(quads []quad.Quad) string {
	var desc string

	for _, q := range quads {
		if p := valToStr(q.Get(quad.Predicate)); p == "description" {
			if obj := valToStr(q.Get(quad.Object)); obj != "" {
				desc = obj
			}
			break
		}
	}

	return desc
}

func isTLD(id string, quads map[string][]quad.Quad) bool {
	var result bool
loop:
	for _, s := range quads {
		for _, q := range s {
			if obj := valToStr(q.Get(quad.Object)); obj == id {
				if p := valToStr(q.Get(quad.Predicate)); p == "tld" {
					result = true
					break loop
				}
			}
		}
	}

	return result
}

func getSource(id string, events []string, quads map[string][]quad.Quad) string {
	var source string
loop:
	for _, event := range events {
		for _, q := range quads[event] {
			if obj := valToStr(q.Get(quad.Object)); obj == id {
				if p := valToStr(q.Get(quad.Predicate)); p != "" && p != "domain" {
					source = p
					break loop
				}
			}
		}
	}

	return source
}

// Identify the edges between nodes that should be included in the visualization.
func vizEdges(nodes []Node, nodeToIdx map[string]int, quads map[string][]quad.Quad) []Edge {
	var edges []Edge

	for _, n := range nodes {
		e := outEdges(quads[n.Label], "root", "cname_record",
			"a_record", "aaaa_record", "ptr_record", "service",
			"srv_record", "ns_record", "mx_record", "contains", "prefix")

		for _, edge := range e {
			pred := valToStr(edge.Get(quad.Predicate))
			obj := valToStr(edge.Get(quad.Object))

			if toID, found := nodeToIdx[obj]; found && pred != "" {
				edges = append(edges, Edge{
					From:  n.ID,
					To:    toID,
					Title: pred,
				})
			}
		}
	}

	return edges
}

func outEdges(quads []quad.Quad, preds ...string) []quad.Quad {
	var results []quad.Quad

	list := stringset.New(preds...)
	defer list.Close()

	for _, q := range quads {
		if p := valToStr(q.Get(quad.Predicate)); p != "" && list.Has(p) {
			results = append(results, q)
		}
	}

	return results
}

// Update the type names for visualization.
func convertNodeType(id, ntype string, quads map[string][]quad.Quad) string {
	if ntype == "fqdn" {
		if in := inEdges(id, quads, "root", "mx_record", "ns_record"); in != "" {
			switch in {
			case "root":
				ntype = "domain"
			case "ns_record":
				ntype = "ns"
			case "mx_record":
				ntype = "mx"
			}
		} else if p := outEdges(quads[id], "ptr_record"); len(p) > 0 {
			ntype = "ptr"
		} else {
			ntype = "subdomain"
		}
	} else if ntype == "ipaddr" {
		ntype = "address"
	}

	return ntype
}

func inEdges(id string, quads map[string][]quad.Quad, preds ...string) string {
	var result string

	list := stringset.New(preds...)
	defer list.Close()

	for _, s := range quads {
		for _, q := range s {
			if obj := valToStr(q.Get(quad.Object)); obj == id {
				if p := valToStr(q.Get(quad.Predicate)); p != "" && list.Has(p) {
					result = p
					break
				}
			}
		}
	}

	return result
}

func valToStr(v quad.Value) string {
	var result string

	if iri, ok := v.Native().(quad.IRI); ok {
		result = strings.TrimRight(strings.TrimLeft(string(iri), "<"), ">")
	} else if str, ok := v.Native().(string); ok {
		result = strings.Trim(str, `"`)
	}

	return result
}
