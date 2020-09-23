// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"testing"

	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
)

func TestInsertEdge(t *testing.T) {
	g := NewCayleyGraphMemory()

	bob := "Bob"
	alice := "Alice"
	vBob := quad.IRI(bob)
	vAlice := quad.IRI(alice)
	vType := quad.IRI("type")

	testArgs := []struct {
		Predicate string
		From      string
		To        string
		ErrMsg    string
	}{
		{
			Predicate: "",
			From:      bob,
			To:        alice,
			ErrMsg:    "InsertEdge returned no error when provided an invalid predicate",
		},
		{
			Predicate: "testing",
			From:      "",
			To:        alice,
			ErrMsg:    "InsertEdge returned no error when provided an empty 'from' node",
		},
		{
			Predicate: "testing",
			From:      bob,
			To:        "",
			ErrMsg:    "InsertEdge returned no error when provided an empty 'to' node",
		},
	}
	for i, test := range testArgs {
		if i == len(testArgs)-1 {
			g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))
		}
		err := g.InsertEdge(&Edge{
			Predicate: test.Predicate,
			From:      test.From,
			To:        test.To,
		})
		if err == nil {
			t.Errorf(test.ErrMsg)
		}
	}

	g.store.AddQuad(quad.Make(vAlice, vType, "Person", nil))

	err := g.InsertEdge(&Edge{
		Predicate: "knows",
		From:      bob,
		To:        alice,
	})
	if err != nil {
		t.Errorf("InsertEdge failed when given a valid edge with existing nodes")
	}

	// Check if the edge was successfully inserted
	p := cayley.StartPath(g.store, vBob).Out(quad.IRI("knows")).Is(vAlice)
	if first, err := p.Iterate(context.Background()).FirstValue(nil); err != nil || first == nil {
		t.Errorf("InsertEdge failed to insert the quad for the edge")
	}

	err = g.InsertEdge(&Edge{
		Predicate: "knows",
		From:      bob,
		To:        alice,
	})
	if err != nil {
		t.Errorf("InsertEdge returned an error when attempting to insert an edge for the second time")
	}
}

func TestReadEdges(t *testing.T) {
	g := NewCayleyGraphMemory()

	if _, err := g.ReadEdges(""); err == nil {
		t.Errorf("ReadEdges returned no error when provided an empty node argument")
	}
	if _, err := g.ReadEdges("Bob"); err == nil {
		t.Errorf("ReadEdges returned no error when the node does not exist")
	}

	vBob := quad.IRI("Bob")
	vType := quad.IRI("type")
	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))

	if _, err := g.ReadEdges("Bob"); err == nil {
		t.Errorf("ReadEdges returned no error when the node has no edges")
	}

	vAlice := quad.IRI("Alice")
	g.store.AddQuad(quad.Make(vAlice, vType, "Person", nil))
	g.store.AddQuad(quad.Make(vBob, quad.IRI("knows"), vAlice, nil))

	if edges, err := g.ReadEdges("Bob"); err != nil {
		t.Errorf("ReadEdges returned an error when the node has edges: %v", err)
	} else if len(edges) != 1 || edges[0].Predicate != "knows" || g.NodeToID(edges[0].To) != "Alice" {
		t.Errorf("ReadEdges returned the wrong edges: %v", edges)
	}

	g.store.AddQuad(quad.Make(vAlice, quad.IRI("knows"), vBob, nil))

	if edges, err := g.ReadEdges("Bob", "knows"); err != nil {
		t.Errorf("ReadEdges returned an error when the node has multiple edges: %v", err)
	} else if len(edges) != 2 {
		t.Errorf("ReadEdges returned the wrong edges: %v", edges)
	}

	if _, err := g.ReadEdges("Bob", "likes"); err == nil {
		t.Errorf("ReadEdges returned no error when the node does not have edges with matching predicates: %v", err)
	}

	g.store.AddQuad(quad.Make(vBob, quad.IRI("likes"), vAlice, nil))

	if edges, err := g.ReadEdges("Bob", "likes"); err != nil {
		t.Errorf("ReadEdges returned an error when the node has edges with matching predicates: %v", err)
	} else if len(edges) != 1 || edges[0].Predicate != "likes" || g.NodeToID(edges[0].To) != "Alice" {
		t.Errorf("ReadEdges returned the wrong edges when provided matching predicates: %v", edges)
	}
}

func TestCountEdges(t *testing.T) {
	g := NewCayleyGraphMemory()

	if count, err := g.CountEdges(""); err == nil {
		t.Errorf("CountEdges returned no error when provided an empty node argument")
	} else if count != 0 {
		t.Errorf("CountEdges did not return zero when provided an empty node argument")
	}
	if count, err := g.CountEdges("Bob"); err == nil {
		t.Errorf("CountEdges returned no error when the node does not exist")
	} else if count != 0 {
		t.Errorf("CountEdges did not return zero when the node does not exist")
	}
	if count, err := g.CountOutEdges("Bob"); err == nil {
		t.Errorf("CountOutEdges returned no error when the node does not exist")
	} else if count != 0 {
		t.Errorf("CountOutEdges did not return zero when the node does not exist")
	}

	vBob := quad.IRI("Bob")
	vType := quad.IRI("type")
	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))

	if count, err := g.CountEdges("Bob"); err != nil {
		t.Errorf("CountEdges returned an error when the node has no edges: %v", err)
	} else if count != 0 {
		t.Errorf("CountEdges returned the wrong count value: %d", count)
	}

	vAlice := quad.IRI("Alice")
	g.store.AddQuad(quad.Make(vAlice, vType, "Person", nil))
	g.store.AddQuad(quad.Make(vBob, quad.IRI("knows"), vAlice, nil))

	if count, err := g.CountEdges("Bob"); err != nil {
		t.Errorf("CountEdges returned an error when the node has edges: %v", err)
	} else if count != 1 {
		t.Errorf("CountEdges returned the wrong count value: %d", count)
	}

	g.store.AddQuad(quad.Make(vAlice, quad.IRI("knows"), vBob, nil))

	if count, err := g.CountEdges("Bob"); err != nil {
		t.Errorf("CountEdges returned an error when the node has multiple edges: %v", err)
	} else if count != 2 {
		t.Errorf("CountEdges returned the wrong count value: %d", count)
	}

	if count, err := g.CountEdges("Bob", "likes"); err != nil {
		t.Errorf("CountEdges returned an error when the node does not have edges with matching predicates: %v", err)
	} else if count != 0 {
		t.Errorf("CountEdges returned the wrong count value when the node does not have edges with matching predicates: %d", count)
	}

	g.store.AddQuad(quad.Make(vBob, quad.IRI("likes"), vAlice, nil))

	if count, err := g.CountEdges("Bob", "likes"); err != nil {
		t.Errorf("CountEdges returned an error when the node has edges with matching predicates: %v", err)
	} else if count != 1 {
		t.Errorf("CountEdges returned the wrong number of edges when provided matching predicates: %d", count)
	}
}

func TestDeleteEdge(t *testing.T) {
	g := NewCayleyGraphMemory()

	bob := "Bob"
	alice := "Alice"
	vBob := quad.IRI(bob)
	vType := quad.IRI("type")

	testArgs := []struct {
		Predicate string
		From      string
		To        string
		ErrMsg    string
	}{
		{
			Predicate: "",
			From:      bob,
			To:        alice,
			ErrMsg:    "DeleteEdge returned no error when provided an invalid predicate",
		},
		{
			Predicate: "testing",
			From:      "",
			To:        alice,
			ErrMsg:    "DeleteEdge returned no error when provided an empty 'from' node",
		},
		{
			Predicate: "testing",
			From:      bob,
			To:        "",
			ErrMsg:    "DeleteEdge returned no error when provided an empty 'to' node",
		},
	}
	for i, test := range testArgs {
		if i == len(testArgs)-1 {
			g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))
		}
		err := g.DeleteEdge(&Edge{
			Predicate: test.Predicate,
			From:      test.From,
			To:        test.To,
		})
		if err == nil {
			t.Errorf(test.ErrMsg)
		}
	}

	vAlice := quad.IRI(alice)
	g.store.AddQuad(quad.Make(vAlice, vType, "Person", nil))

	err := g.DeleteEdge(&Edge{
		Predicate: "knows",
		From:      bob,
		To:        alice,
	})
	if err == nil {
		t.Errorf("DeleteEdge returned no error when provided an edge that does not exist")
	}

	g.store.AddQuad(quad.Make(vBob, quad.IRI("knows"), vAlice, nil))

	err = g.DeleteEdge(&Edge{
		Predicate: "knows",
		From:      bob,
		To:        alice,
	})
	if err != nil {
		t.Errorf("DeleteEdge returned an error when provided a valid edge: %v", err)
	}

	// Check if the edge was actually removed
	p := cayley.StartPath(g.store, vBob).Out(quad.IRI("knows")).Is(vAlice)
	if first, err := p.Iterate(context.Background()).FirstValue(nil); err == nil && first != nil {
		t.Errorf("DeleteEdge failed to remove the edge")
	}
}
