// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"fmt"

	"github.com/OWASP/Amass/v3/graphdb"
)

// MigrateEvent copies the nodes and edges related to the Event identified by the uuid from the receiver Graph into another.
func (g *Graph) MigrateEvent(uuid string, to *Graph) error {
	fnodes := make(map[string]graphdb.Node)
	tnodes := make(map[string]graphdb.Node)

	event, err := g.db.ReadNode(uuid, "event")
	if err != nil {
		return fmt.Errorf("Graph: Migrate: Failed to read the event node for %s: %v", uuid, err)
	}

	edges, err := g.db.ReadOutEdges(event)
	if err != nil {
		return fmt.Errorf("Graph: Migrate: Failed to read the edges from event node %s: %v", uuid, err)
	}

	// Copy the event node into the graph
	node, err := g.migrateNode(uuid, event, to)
	if err != nil {
		return fmt.Errorf("Graph: Migrate: Failed to copy node %s: %v", uuid, err)
	}

	fnodes[uuid] = event
	tnodes[uuid] = node

	// Copy all remaining nodes into the graph
	for _, edge := range edges {
		id := g.db.NodeToID(edge.To)

		// Check if this node has already been migrated
		if _, found := fnodes[id]; found {
			continue
		}

		node, err = g.migrateNode(id, edge.To, to)
		if err != nil {
			return fmt.Errorf("Graph: Migrate: Failed to copy node %s: %v", id, err)
		}

		fnodes[id] = edge.To
		tnodes[id] = node
	}

	// Create all the edges between the copied nodes
	for id, node := range fnodes {
		ins, err := g.db.ReadInEdges(node)
		if err != nil {
			continue
		}

		for _, edge := range ins {
			fid := g.db.NodeToID(edge.From)

			// Nodes from other events, and edges to those nodes, are not to be included
			if _, found := tnodes[fid]; !found {
				continue
			}

			err = to.InsertEdge(&graphdb.Edge{
				Predicate: edge.Predicate,
				From:      tnodes[fid],
				To:        tnodes[id],
			})
			if err != nil {
				return fmt.Errorf("Graph: Migrate: Failed to create the edge from node %s to node %s: %v", fid, id, err)
			}
		}
	}

	return nil
}

func (g *Graph) migrateNode(id string, node graphdb.Node, to *Graph) (graphdb.Node, error) {
	// Obtain the properties of the Node being migrated
	properties, err := g.db.ReadProperties(node)
	if err != nil || len(properties) == 0 {
		return nil, fmt.Errorf("migrateNode: Properties for the %s node %s could not be obtained: %v", g.String(), id, err)
	}

	// Obtain the type of the Node being migrated
	ntype := getTypeFromProperties(properties)
	if ntype == "" {
		return nil, fmt.Errorf("migrateNode: Unable to obtain the type for the %s node %s: %v", g.String(), id, err)
	}

	// Check if this node already exists in the 'to' graph
	tonode, err := to.db.ReadNode(id, ntype)
	if err != nil {
		// Create the Node in the Graph
		tonode, err = to.db.InsertNode(id, ntype)
		if err != nil {
			return nil, fmt.Errorf("migrateNode: Failed to insert the %s node %s: %v", g.String(), id, err)
		}
	}

	// Copy all the properties into the Node being migrated
	if err := g.migrateProperties(tonode, properties, to); err != nil {
		return nil, fmt.Errorf("migrateNode: Failed to migrate properties for the %s node %s: %v", g.String(), id, err)
	}

	return tonode, nil
}

func (g *Graph) migrateProperties(node graphdb.Node, properties []*graphdb.Property, to *Graph) error {
	for _, p := range properties {
		if p.Predicate == "type" {
			continue
		}

		if err := to.db.InsertProperty(node, p.Predicate, p.Value); err != nil {
			return err
		}
	}

	return nil
}

func getTypeFromProperties(properties []*graphdb.Property) string {
	var ntype string

	for _, p := range properties {
		if p.Predicate == "type" {
			ntype = p.Value
			break
		}
	}

	return ntype
}
