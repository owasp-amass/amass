// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graphdb

import (
	"fmt"
)

// Constant values that represent the direction of edges during graph queries.
const (
	IN int = iota
	OUT
	BOTH
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

	NodeToID(node Node) string
	// Provides all nodes in the graph of the identified types
	AllNodesOfType(ntypes ...string) ([]Node, error)

	// Graph operations for adding and removing nodes
	InsertNode(id, ntype string) (Node, error)
	ReadNode(id, ntype string) (Node, error)
	DeleteNode(node Node) error

	// Graph operations for manipulating properties of a node
	InsertProperty(node Node, predicate, value string) error
	ReadProperties(node Node, predicates ...string) ([]*Property, error)
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

	// Signals the database to close
	Close()
}
