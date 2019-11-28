// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package db

import (
	"fmt"
)

// Node represents a node in the graph.
type Node interface{}

// Property represents a node property.
type Property struct {
	Predicate string
	Value     string
}

// Edge represents an edge in the graph.
type Edge struct {
	Predicate string
	From, To  Node
}

// GraphDatabase is the interface for storage of Amass data.
type GraphDatabase interface {
	fmt.Stringer

	// Graph operations for adding and removing nodes
	NodeToID(n Node) string
	InsertNode(id, ntype string) (Node, error)
	ReadNode(name string) (Node, error)
	DeleteNode(node Node) error

	// Graph operations for querying for nodes using search criteria
	AllNodesOfType(ntype string, events ...string) ([]Node, error)
	NameToIPAddrs(node Node) ([]Node, error)

	// NodeSources returns the names of data sources that identified node during the events
	NodeSources(node Node, events ...string) ([]string, error)

	// Graph operations for manipulating property values of a node
	InsertProperty(node Node, predicate, value string) error
	// Returns a slice of predicate names and slice of the associated values
	ReadProperties(node Node, predicates ...string) ([]*Property, error)
	// Returns the number of values for the node that match the optional predicate names
	CountProperties(node Node, predicates ...string) (int, error)
	DeleteProperty(node Node, predicate, value string) error

	// Graph operations for adding and removing edges
	InsertEdge(edge *Edge) error
	ReadEdges(node Node, predicates ...string) ([]*Edge, error)
	ReadInEdges(node Node, predicates ...string) ([]*Edge, error)
	CountInEdges(node Node, predicates ...string) (int, error)
	ReadOutEdges(node Node, predicates ...string) ([]*Edge, error)
	CountOutEdges(node Node, predicates ...string) (int, error)
	DeleteEdge(edge *Edge) error

	// Signals for the database to close
	Close()
}
