// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"math/rand"

	"github.com/OWASP/Amass/v3/viz"
	"github.com/caffix/stringset"
)

// VizData returns the current state of the Graph as viz package Nodes and Edges.
func (g *Graph) VizData(uuids []string) ([]viz.Node, []viz.Edge) {
	var nextIdx int
	var nodes []viz.Node
	ids := stringset.New()
	nodeToIdx := make(map[string]int)

	for i := len(uuids) - 1; i >= 0; i-- {
		event, err := g.db.ReadNode(uuids[i], "event")
		if err != nil {
			continue
		}

		discovered, err := g.db.ReadOutEdges(event)
		if err != nil {
			continue
		}

		var n []viz.Node
		n, nextIdx = g.vizNodes(uuids[i], ids, nextIdx, nodeToIdx, discovered)
		nodes = append(nodes, n...)
	}

	return nodes, g.vizEdges(uuids, nodes, nodeToIdx)
}

// Identify unique nodes that should be included in the visualization.
func (g *Graph) vizNodes(uuid string, filter stringset.Set, idx int, nodeToIdx map[string]int, edges []*Edge) ([]viz.Node, int) {
	var nodes []viz.Node

	for _, d := range edges {
		if id := g.db.NodeToID(d.To); id != "" && !filter.Has(id) {
			filter.Insert(id)

			properties, err := g.db.ReadProperties(d.To, "type")
			// We do not print the source, event or response nodes in the graph visualizations
			if err != nil || len(properties) == 0 ||
				properties[0].Value == "source" ||
				properties[0].Value == "event" ||
				properties[0].Value == "response" {
				continue
			}

			// We do not print the TLD nodes in the graph visualizations
			if g.IsTLDNode(id) {
				continue
			}

			if n := g.buildVizNode(d.To, properties[0].Value, uuid); n != nil {
				n.ID = idx
				// Keep track of which indices nodes were assigned to
				nodeToIdx[id] = idx
				idx++
				nodes = append(nodes, *n)
			}
		}
	}

	return nodes, idx
}

// Identify the edges between nodes that should be included in the visualization.
func (g *Graph) vizEdges(uuids []string, nodes []viz.Node, nodeToIdx map[string]int) []viz.Edge {
	var edges []viz.Edge

	uuidIdx := make(map[string]int, len(uuids))
	for idx, uuid := range uuids {
		uuidIdx[uuid] = idx
	}

	for _, n := range nodes {
		node, err := g.db.ReadNode(n.Label, n.ActualType)
		if err != nil {
			continue
		}

		e, err := g.db.ReadOutEdges(node, "root", "cname_record",
			"a_record", "aaaa_record", "ptr_record", "service",
			"srv_record", "ns_record", "mx_record", "contains", "prefix")
		if err != nil || len(e) == 0 {
			continue
		}

		var newest int
		for _, edge := range e {
			if edge.Predicate != "a_record" && edge.Predicate != "aaaa_record" {
				continue
			}
			if events, err := g.db.ReadInEdges(edge.To, "DNS"); err == nil {
				for _, event := range events {
					if idx := uuidIdx[g.db.NodeToID(event.From)]; idx > newest {
						newest = idx
					}
				}
			}
		}

		for _, edge := range e {
			if edge.Predicate == "a_record" || edge.Predicate == "aaaa_record" {
				var use bool
				if events, err := g.db.ReadInEdges(edge.To, "DNS"); err == nil {
					for _, event := range events {
						if idx := uuidIdx[g.db.NodeToID(event.From)]; idx == newest {
							use = true
							break
						}
					}
				}
				if !use {
					continue
				}
			}
			if toID, found := nodeToIdx[g.db.NodeToID(edge.To)]; found {
				edges = append(edges, viz.Edge{
					From:  n.ID,
					To:    toID,
					Title: edge.Predicate,
				})
			}
		}
	}

	return edges
}

func (g *Graph) buildVizNode(node Node, ntype, uuid string) *viz.Node {
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

	newtype := g.convertNodeType(id, ntype, edges)
	title := newtype + ": " + id
	if newtype == "as" {
		title = title + ", Desc: " + g.ReadASDescription(id)
	}

	return &viz.Node{
		Type:       newtype,
		Label:      id,
		Title:      title,
		Source:     src,
		ActualType: ntype,
	}
}

// Update the type names for visualization.
func (g *Graph) convertNodeType(id, ntype string, edges []*Edge) string {
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

	return ntype
}

func randomIndex(length int) int {
	if length == 1 {
		return 0
	}

	return rand.Intn(length - 1)
}
