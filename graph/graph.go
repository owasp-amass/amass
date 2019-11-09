// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"github.com/OWASP/Amass/v3/graph/db"
)

// Graph implements the Amass network infrastructure data model.
type Graph struct {
	db            db.GraphDatabase
	alreadyClosed bool
}

// NewGraph accepts a graph database that stores the Graph created and maintained by the data model.
func NewGraph(database db.GraphDatabase) *Graph {
	if database == nil {
		return nil
	}

	return &Graph{db: database}
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

// InsertEdge will create an edge in the database if it does not already exist.
func (g *Graph) InsertEdge(edge *db.Edge) error {
	// Check if this edge already exists in the graph
	edges, err := g.db.ReadOutEdges(edge.From, edge.Predicate)
	if err == nil && len(edges) > 0 {
		tstr := g.db.NodeToID(edge.To)

		for _, e := range edges {
			if g.db.NodeToID(e.To) == tstr {
				return nil
			}
		}
	}

	// The edge does not yet exist in the graph
	return g.db.InsertEdge(edge)
}
