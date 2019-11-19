// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"sync"

	"github.com/OWASP/Amass/v3/graph/db"
)

// Graph implements the Amass network infrastructure data model.
type Graph struct {
	db            db.GraphDatabase
	alreadyClosed bool

	// eventFinishes maintains a cache of the latest finish time for each event
	// This reduces roundtrips to the graph when adding nodes to events.
	eventFinishes   map[string]string
	eventFinishLock sync.Mutex
}

// NewGraph accepts a graph database that stores the Graph created and maintained by the data model.
func NewGraph(database db.GraphDatabase) *Graph {
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
func (g *Graph) InsertNodeIfNotExist(id, ntype string) (db.Node, error) {
	node, err := g.db.ReadNode(id)
	if err != nil {
		node, err = g.db.InsertNode(id, ntype)
	}

	return node, err
}

// InsertEdge will create an edge in the database if it does not already exist.
func (g *Graph) InsertEdge(edge *db.Edge) error {
	return g.db.InsertEdge(edge)
}
