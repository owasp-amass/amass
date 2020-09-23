// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"testing"

	"github.com/OWASP/Amass/v3/stringset"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
)

func TestInsertProperty(t *testing.T) {
	g := NewCayleyGraphMemory()

	if err := g.InsertProperty("", "like", "coffee"); err == nil {
		t.Errorf("InsertProperty returned no error when provided an empty node argument")
	}

	if err := g.InsertProperty("Bob", "like", "Go"); err == nil {
		t.Errorf("InsertProperty returned no error when provided a node that doesn't exist")
	}

	vBob := quad.IRI("Bob")
	vType := quad.IRI("type")
	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))

	if err := g.InsertProperty("Bob", "", "coffee"); err == nil {
		t.Errorf("InsertProperty returned no error when provided an empty predicate argument")
	}

	if err := g.InsertProperty("Bob", "likes", "coffee"); err != nil {
		t.Errorf("InsertProperty returned an error when provided a valid node and property arguments")
	}

	p := cayley.StartPath(g.store, vBob).Has(quad.IRI("likes"), quad.String("coffee"))
	if first, err := p.Iterate(context.Background()).FirstValue(nil); err != nil || first == nil {
		t.Errorf("InsertProperty failed to enter the property for the node")
	}

	// A second attempt to insert the property should return no error
	if err := g.InsertProperty("Bob", "likes", "coffee"); err != nil {
		t.Errorf("InsertProperty returned no error when attempting the insertion twice")
	}
}

func TestReadProperties(t *testing.T) {
	g := NewCayleyGraphMemory()

	if _, err := g.ReadProperties("", "likes"); err == nil {
		t.Errorf("ReadProperties returned no error when provided an empty node argument")
	}

	if _, err := g.ReadProperties("Bob", "likes"); err == nil {
		t.Errorf("ReadProperties returned no error when provided a node that doesn't exist")
	}

	vBob := quad.IRI("Bob")
	vType := quad.IRI("type")
	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))

	properties, err := g.ReadProperties("Bob")
	if err != nil {
		t.Errorf("ReadProperties returned an error when provided a valid node")
	}

	got := stringset.New()
	expected := stringset.New()
	expected.InsertMany("Person")
	for _, property := range properties {
		got.Insert(property.Value)
	}
	expected.Subtract(got)
	if expected.Len() != 0 {
		t.Errorf("ReadProperties did not return the expected property: %v", got.Slice())
	}

	vLikes := quad.IRI("likes")
	g.store.AddQuad(quad.Make(vBob, vLikes, "coffee", nil))
	g.store.AddQuad(quad.Make(vBob, vLikes, "Go", nil))

	properties, err = g.ReadProperties("Bob")
	if err != nil {
		t.Errorf("ReadProperties returned an error when provided a valid node")
	}

	got = stringset.New()
	expected = stringset.New()
	expected.InsertMany("Person", "coffee", "Go")
	for _, property := range properties {
		got.Insert(property.Value)
	}
	expected.Subtract(got)
	if expected.Len() != 0 {
		t.Errorf("ReadProperties did not return the expected properties: %v", got.Slice())
	}

	properties, err = g.ReadProperties("Bob", "likes")
	if err != nil {
		t.Errorf("ReadProperties returned an error when provided a valid node")
	}

	got = stringset.New()
	expected = stringset.New()
	expected.InsertMany("coffee", "Go")
	for _, property := range properties {
		got.Insert(property.Value)
	}
	expected.Subtract(got)
	if expected.Len() != 0 {
		t.Errorf("ReadProperties did not return the expected properties: %v", got.Slice())
	}
}

func TestCountProperties(t *testing.T) {
	g := NewCayleyGraphMemory()

	if _, err := g.CountProperties("", "likes"); err == nil {
		t.Errorf("CountProperties returned no error when provided an empty node argument")
	}

	if _, err := g.CountProperties("Bob", "likes"); err == nil {
		t.Errorf("CountProperties returned no error when provided a node that doesn't exist")
	}

	vBob := quad.IRI("Bob")
	vType := quad.IRI("type")
	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))

	if count, err := g.CountProperties("Bob"); err != nil {
		t.Errorf("CountProperties returned an error when provided a valid node")
	} else if count != 1 {
		t.Errorf("CountProperties returned an incorrect count for a valid node")
	}

	vLikes := quad.IRI("likes")
	g.store.AddQuad(quad.Make(vBob, vLikes, "coffee", nil))
	g.store.AddQuad(quad.Make(vBob, vLikes, "Go", nil))

	if count, err := g.CountProperties("Bob"); err != nil {
		t.Errorf("CountProperties returned an error when provided a valid node with additional properties")
	} else if count != 3 {
		t.Errorf("CountProperties returned an incorrect count for a valid node with additional properties")
	}

	if count, err := g.CountProperties("Bob", "likes"); err != nil {
		t.Errorf("CountProperties returned an error when provided a valid node, additional properties and a constraint")
	} else if count != 2 {
		t.Errorf("CountProperties returned an incorrect count for a valid node, additional properties and a constraint")
	}
}

func TestDeleteProperty(t *testing.T) {
	g := NewCayleyGraphMemory()

	if err := g.DeleteProperty("", "likes", "coffee"); err == nil {
		t.Errorf("DeleteProperty returned no error when provided an empty node argument")
	}

	if err := g.DeleteProperty("Bob", "likes", "Go"); err == nil {
		t.Errorf("DeleteProperty returned no error when provided a node that doesn't exist")
	}

	vBob := quad.IRI("Bob")
	vType := quad.IRI("type")
	vLikes := quad.IRI("likes")
	// setup the initial data in the graph
	g.store.AddQuad(quad.Make(vBob, vType, "Person", nil))
	g.store.AddQuad(quad.Make(vBob, vLikes, "coffee", nil))

	if err := g.DeleteProperty("Bob", "likes", "coffee"); err != nil {
		t.Errorf("DeleteProperty returned an error when provided a valid node and property arguments")
	}

	p := cayley.StartPath(g.store, vBob).Has(quad.IRI("likes"), quad.String("coffee"))
	if first, err := p.Iterate(context.Background()).FirstValue(nil); err == nil && first != nil {
		t.Errorf("DeleteProperty failed to delete the property from the node")
	}

	if err := g.DeleteProperty("Bob", "likes", "coffee"); err == nil {
		t.Errorf("DeleteProperty returned no error when attempting to delete a property for the second time")
	}
}
