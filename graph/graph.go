// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"errors"
	"sync"
)

// Graph implements the Amass network infrastructure data model.
type Graph struct {
	db            *CayleyGraph
	alreadyClosed bool

	// eventFinishes maintains a cache of the latest finish time for each event
	// This reduces roundtrips to the graph when adding nodes to events.
	eventFinishes   map[string]string
	eventFinishLock sync.Mutex
}

// NewGraph accepts a graph database that stores the Graph created and maintained by the data model.
func NewGraph(database *CayleyGraph) *Graph {
	if database == nil {
		return nil
	}

	return &Graph{
		db:            database,
		eventFinishes: make(map[string]string),
	}
}

// Close will close the graph database being used by the Graph receiver.
func (g *Graph) Close() {
	if !g.alreadyClosed {
		g.alreadyClosed = true
		g.db.Close()
	}
}

// String returns the name of the graph database used by the Graph.
func (g *Graph) String() string {
	return g.db.String()
}

// InsertNodeIfNotExist will create a node in the database if it does not already exist.
func (g *Graph) InsertNodeIfNotExist(id, ntype string) (Node, error) {
	node, err := g.db.ReadNode(id, ntype)
	if err != nil {
		node, err = g.db.InsertNode(id, ntype)
	}

	return node, err
}

// InsertEdge will create an edge in the database if it does not already exist.
func (g *Graph) InsertEdge(edge *Edge) error {
	return g.db.InsertEdge(edge)
}

// AllNodesOfType provides all nodes in the graph of the identified
// type within the optionally identified events.
func (g *Graph) AllNodesOfType(ntype string, events ...string) ([]Node, error) {
	var results []Node

	nodes, err := g.db.AllNodesOfType(ntype)
	if err != nil {
		return results, errors.New("Graph: AllNodesOfType: Failed to obtain nodes")
	}

	if len(events) == 0 {
		return nodes, nil
	}

	for _, node := range nodes {
		for _, event := range events {
			var found bool

			// The event type is a special case
			if ntype == "event" {
				if g.db.NodeToID(node) == event {
					found = true
				}
			} else if g.InEventScope(node, event) {
				found = true
			}

			if found {
				results = append(results, node)
				break
			}
		}
	}

	if len(results) == 0 {
		return results, errors.New("Graph: AllNodesOfType: No nodes found")
	}

	return results, nil
}

// DumpGraph prints all data currently in the graph.
func (g *Graph) DumpGraph() string {
	return g.db.DumpGraph()
}
