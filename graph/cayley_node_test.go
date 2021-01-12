// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"testing"

	"github.com/caffix/stringset"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
)

func TestNodeToID(t *testing.T) {
	id := "test"
	g := NewCayleyGraphMemory()

	if node := Node(id); g.NodeToID(node) != id {
		t.Errorf("The graph node id was not properly returned by NodeToID")
	}
}

func TestAllNodesOfType(t *testing.T) {
	g := NewCayleyGraphMemory()

	if nodes, err := g.AllNodesOfType(); err == nil {
		t.Errorf("AllNodesOfType returned no error for an empty graph")
	} else if len(nodes) > 0 {
		t.Errorf("AllNodesOfType returned a non-empty slice of nodes on an empty graph")
	}

	// setup the data in the graph
	g.store.AddQuad(quad.Make(quad.IRI("test"), quad.IRI("type"), quad.String("test"), nil))

	if nodes, err := g.AllNodesOfType(); err != nil {
		t.Errorf("AllNodesOfType returned an error for a non-empty graph and no constraints")
	} else if len(nodes) == 0 {
		t.Errorf("AllNodesOfType returned an empty slice of nodes for a non-empty graph and no constraints")
	}

	if nodes, err := g.AllNodesOfType("test"); err != nil {
		t.Errorf("AllNodesOfType returned an error for a non-empty graph and matching constraints")
	} else if len(nodes) == 0 {
		t.Errorf("AllNodesOfType returned an empty slice of nodes for a non-empty graph and matching constraints")
	}

	if nodes, err := g.AllNodesOfType("do_not_match"); err == nil {
		t.Errorf("AllNodesOfType returned no error for a non-empty graph and differing constraints")
	} else if len(nodes) > 0 {
		t.Errorf("AllNodesOfType returned non-empty slice of nodes for a non-empty graph and differing constraints")
	}
}

func TestAllOutNodes(t *testing.T) {
	g := NewCayleyGraphMemory()

	vBob := quad.IRI("Bob")
	vAlice := quad.IRI("Alice")
	vCharles := quad.IRI("Charles")
	knows := quad.IRI("knows")
	vType := quad.IRI("type")

	if nodes, err := g.AllOutNodes("Bob"); err == nil {
		t.Errorf("AllOutNodes returned no error for an empty graph")
	} else if len(nodes) > 0 {
		t.Errorf("AllOutNodes returned a non-empty slice of nodes on an empty graph")
	}

	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, knows, vAlice, nil))
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))
	g.store.AddQuad(quad.Make(vAlice, knows, vCharles, nil))
	g.store.AddQuad(quad.Make(vAlice, vType, "Person", nil))
	g.store.AddQuad(quad.Make(vCharles, knows, vAlice, nil))
	g.store.AddQuad(quad.Make(vCharles, vType, "Person", nil))

	if nodes, err := g.AllOutNodes("Bob"); err != nil {
		t.Errorf("AllOutNodes returned an error when out nodes existed from the node")
	} else if len(nodes) != 1 {
		t.Errorf("AllOutNodes returned the incorrent number of nodes in the slice")
	} else if g.NodeToID(nodes[0]) != "Alice" {
		t.Errorf("AllOutNodes returned a slice with the wrong node")
	}

	g.store.AddQuad(quad.Make(vBob, knows, vCharles, nil))

	nodes, err := g.AllOutNodes("Bob")
	if err != nil {
		t.Errorf("AllOutNodes returned an error when out nodes existed from the node")
	} else if len(nodes) != 2 {
		t.Errorf("AllOutNodes returned the incorrent number of nodes in the slice")
	}

	got := stringset.New()
	expected := stringset.New()
	expected.InsertMany("Alice", "Charles")
	for _, node := range nodes {
		got.Insert(g.NodeToID(node))
	}
	expected.Subtract(got)
	if expected.Len() != 0 {
		t.Errorf("AllOutNodes returned a slice with the wrong nodes: %v", got.Slice())
	}
}

func TestInsertNode(t *testing.T) {
	name := "test"
	g := NewCayleyGraphMemory()

	if _, err := g.InsertNode("", name); err == nil {
		t.Errorf("InsertNode did not return an error when the id is invalid")
	}

	if _, err := g.InsertNode(name, ""); err == nil {
		t.Errorf("InsertNode did not return an error when the type is invalid")
	}

	if node, err := g.InsertNode(name, name); err != nil {
		t.Errorf("InsertNode returned an error when the arguments are valid")
	} else if g.NodeToID(node) != name {
		t.Errorf("InsertNode did not return the node with the correct identifier")
	}
	// Try to insert the same node again
	if node, err := g.InsertNode(name, name); err != nil {
		t.Errorf("InsertNode returned an error on a second execution with the same valid arguments")
	} else if g.NodeToID(node) != name {
		t.Errorf("InsertNode did not return the node with the correct identifier on a second execution with the same valid arguments")
	}

	// Check if the node was properly entered into the graph database
	p := cayley.StartPath(g.store, quad.IRI(name)).Has(quad.IRI("type"), quad.String(name))
	if first, err := p.Iterate(context.Background()).FirstValue(nil); err != nil || valToStr(first) != "test" {
		t.Errorf("InsertNode failed to enter the node: expected %s and got %s", name, valToStr(first))
	}
}

func TestReadNode(t *testing.T) {
	g := NewCayleyGraphMemory()

	bob := "Bob"
	bType := "Person"
	vBob := quad.IRI(bob)
	vType := quad.IRI("type")

	if _, err := g.ReadNode("", bType); err == nil {
		t.Errorf("ReadNode returned no error when given an invalid id argument")
	}
	if _, err := g.ReadNode(bob, ""); err == nil {
		t.Errorf("ReadNode returned no error when given an invalid type argument")
	}
	if _, err := g.ReadNode(bob, bType); err == nil {
		t.Errorf("ReadNode returned no error when given arguments for a non-existent node")
	}

	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, vType, bType, nil))

	if node, err := g.ReadNode(bob, bType); err != nil {
		t.Errorf("ReadNode returned an error when given valid arguments")
	} else if g.NodeToID(node) != bob {
		t.Errorf("ReadNode returned a node that does not match the arguments")
	}
}

func TestDeleteNode(t *testing.T) {
	g := NewCayleyGraphMemory()

	if err := g.DeleteNode(""); err == nil {
		t.Errorf("DeleteNode returned no error when provided an invalid argument")
	}

	vBob := quad.IRI("Bob")
	vAlice := quad.IRI("Alice")
	vCharles := quad.IRI("Charles")
	knows := quad.IRI("knows")
	likes := quad.IRI("likes")
	vType := quad.IRI("type")

	if err := g.DeleteNode("Bob"); err == nil {
		t.Errorf("DeleteNode returned no error when the argument node did not exist")
	}

	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, knows, vAlice, nil))
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))
	g.store.AddQuad(quad.Make(vBob, knows, vCharles, nil))
	g.store.AddQuad(quad.Make(vCharles, vType, "Person", nil))
	g.store.AddQuad(quad.Make(vBob, likes, "Go", nil))
	g.store.AddQuad(quad.Make(vBob, likes, "Automation", nil))

	if err := g.DeleteNode("Bob"); err != nil {
		t.Errorf("DeleteNode returned an error when provide a valid argument for an existing node")
	}

	// Check that no quads with 'Bob' as a subject exist
	p := cayley.StartPath(g.store, vBob).Out()
	if count, err := p.Iterate(context.Background()).Count(); err == nil && count != 0 {
		t.Errorf("DeleteNode did not remove all the quads with 'Bob' as the subject")
	}
}

func TestWriteNodeQuads(t *testing.T) {
	g := NewCayleyGraphMemory()
	defer g.Close()

	vBob := quad.IRI("Bob")
	vAlice := quad.IRI("Alice")
	vCharles := quad.IRI("Charles")
	knows := quad.IRI("knows")
	vType := quad.IRI("type")
	// setup the initial data in the graph
	expected := stringset.New()
	g.store.AddQuad(quad.Make(vBob, knows, vAlice, nil))
	expected.Insert("BobknowsAlice")
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))
	expected.Insert("BobtypePerson")
	g.store.AddQuad(quad.Make(vAlice, knows, vCharles, nil))
	expected.Insert("AliceknowsCharles")
	g.store.AddQuad(quad.Make(vAlice, vType, "Person", nil))
	expected.Insert("AlicetypePerson")
	g.store.AddQuad(quad.Make(vCharles, knows, vAlice, nil))
	expected.Insert("CharlesknowsAlice")
	g.store.AddQuad(quad.Make(vCharles, vType, "Person", nil))
	expected.Insert("CharlestypePerson")

	dup := NewCayleyGraphMemory()
	nodes, _ := g.AllNodesOfType("Person")
	if err := dup.WriteNodeQuads(g, nodes); err != nil {
		t.Errorf("WriteNodeQuads returned an error when provided valid arguments")
	}

	got := stringset.New()
	p := cayley.StartPath(dup.store).Tag("subject").OutWithTags([]string{"predicate"}).Tag("object")
	p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		sub := valToStr(m["subject"])
		pred := valToStr(m["predicate"])
		obj := valToStr(m["object"])
		got.Insert(sub + pred + obj)
	})

	expected.Subtract(got)
	if expected.Len() != 0 {
		t.Errorf("WriteNodeQuads did not replicate all the quads")
	}
}
