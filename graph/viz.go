// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"github.com/OWASP/Amass/v3/graph/db"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/OWASP/Amass/v3/viz"
)

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func (g *Graph) VizData(uuid string) ([]viz.Node, []viz.Edge) {
	event, err := g.db.ReadNode(uuid)
	if err != nil {
		return nil, nil
	}

	discovered, err := g.db.ReadOutEdges(event)
	if err != nil {
		return nil, nil
	}

	var idx int
	var nodes []viz.Node
	ids := stringset.New()
	rnodes := make(map[string]int)
	// Identify unique nodes that should be included in the visualization
	for _, d := range discovered {
		if id := g.db.NodeToID(d.To); id != "" && !ids.Has(id) {
			ids.Insert(id)

			properties, err := g.db.ReadProperties(d.To, "type")
			if err != nil || len(properties) == 0 || properties[0].Value == "source" {
				continue
			}

			if g.IsTLDNode(id) {
				continue
			}

			if n := g.buildVizNode(d.To, properties[0].Value, uuid); n != nil {
				n.ID = idx
				// Keep track of which indices nodes were assigned to
				rnodes[id] = idx
				idx++
				nodes = append(nodes, *n)
			}
		}
	}

	var edges []viz.Edge
	// Identify the edges between nodes that should be included in the visualization
	for _, n := range nodes {
		node, err := g.db.ReadNode(n.Label)
		if err != nil {
			continue
		}

		e, err := g.db.ReadOutEdges(node, "root", "cname_record",
			"a_record", "aaaa_record", "ptr_record", "service",
			"srv_record", "ns_record", "mx_record", "contains", "prefix")
		if err != nil || len(e) == 0 {
			continue
		}

		for _, edge := range e {
			if toID, found := rnodes[g.db.NodeToID(edge.To)]; found {
				edges = append(edges, viz.Edge{
					From:  n.ID,
					To:    toID,
					Title: edge.Predicate,
				})
			}
		}
	}

	return nodes, edges
}

func (g *Graph) buildVizNode(node db.Node, ntype, uuid string) *viz.Node {
	id := g.db.NodeToID(node)

	edges, err := g.db.ReadInEdges(node)
	if err != nil && len(edges) == 0 {
		return nil
	}

	var sources []string
	// Select one of the data sources to be used in the visualization
	for _, edge := range edges {
		if g.db.NodeToID(edge.From) == uuid {
			sources = append(sources, edge.Predicate)
		}
	}

	if len(sources) == 0 {
		return nil
	}
	src := sources[randomIndex(len(sources))]

	// Update the type names for visualization
	if ntype == "fqdn" {
		var pred string
		// Look for edge predicates of interest
		for _, edge := range edges {
			if edge.Predicate == "root" ||
				edge.Predicate == "mx_record" ||
				edge.Predicate == "ns_record" {
				pred = edge.Predicate
				break
			}
		}

		if pred != "" {
			switch pred {
			case "root":
				ntype = "domain"
			case "ns_record":
				ntype = "ns"
			case "mx_record":
				ntype = "mx"
			}
		} else if g.IsPTRNode(id) {
			ntype = "ptr"
		} else {
			ntype = "subdomain"
		}
	} else if ntype == "ipaddr" {
		ntype = "address"
	}

	title := ntype + ": " + id
	if ntype == "as" {
		title = title + ", Desc: " + g.ReadASDescription(id)
	}

	return &viz.Node{
		Type:   ntype,
		Label:  id,
		Title:  title,
		Source: src,
	}
}
