// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"errors"
	"sync"

	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
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

// ReadNode returns the node matching the id and type arguments.
func (g *Graph) ReadNode(id, ntype string) (Node, error) {
	return g.db.ReadNode(id, ntype)
}

// AllNodesOfType provides all nodes in the graph of the identified
// type within the optionally identified events.
func (g *Graph) AllNodesOfType(ntype string, events ...string) ([]Node, error) {
	var nodes []Node

	for _, id := range g.nodeIDsOfType(ntype, events...) {
		if node, err := g.db.ReadNode(id, ntype); err == nil {
			nodes = append(nodes, node)
		}
	}

	if len(nodes) == 0 {
		return nil, errors.New("Graph: AllNodesOfType: No nodes found")
	}
	return nodes, nil
}

func (g *Graph) nodeIDsOfType(ntype string, events ...string) []string {
	g.db.Lock()
	defer g.db.Unlock()

	var eventVals []quad.Value
	for _, event := range events {
		eventVals = append(eventVals, quad.IRI(event))
	}

	p := cayley.StartPath(g.db.store, eventVals...)
	if ntype != "event" {
		p = p.Out()
	}

	var ids []string
	p = p.Has(quad.IRI("type"), quad.String(ntype)).Unique()
	p.Iterate(context.Background()).EachValue(nil, func(value quad.Value) {
		ids = append(ids, valToStr(value))
	})

	return ids
}

// DumpGraph prints all data currently in the graph.
func (g *Graph) DumpGraph() string {
	return g.db.DumpGraph()
}
