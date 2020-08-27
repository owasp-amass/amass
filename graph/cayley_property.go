// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"fmt"

	"github.com/OWASP/Amass/v3/stringset"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
)

// Property represents a node property.
type Property struct {
	Predicate string
	Value     string
}

// InsertProperty implements the GraphDatabase interface.
func (g *CayleyGraph) InsertProperty(node Node, predicate, value string) error {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" || !g.nodeExists(nstr, "") {
		return fmt.Errorf("%s: InsertProperty: Invalid node reference argument", g.String())
	} else if predicate == "" {
		return fmt.Errorf("%s: InsertProperty: Empty predicate argument", g.String())
	}

	if !g.isBolt || !g.noSync {
		// Check if the property has already been inserted
		p := cayley.StartPath(g.store, quad.IRI(nstr)).Has(quad.IRI(predicate), quad.String(value))
		if first := g.optimizedFirst(p); first != nil {
			return nil
		}
	}

	return g.store.AddQuad(quad.Make(quad.IRI(nstr), quad.IRI(predicate), quad.String(value), nil))
}

// ReadProperties implements the GraphDatabase interface.
func (g *CayleyGraph) ReadProperties(node Node, predicates ...string) ([]*Property, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	var properties []*Property

	if nstr == "" || !g.nodeExists(nstr, "") {
		return properties, fmt.Errorf("%s: ReadProperties: Invalid node reference argument", g.String())
	}

	var preds []interface{}
	filter := stringset.New()
	for _, pred := range predicates {
		if !filter.Has(pred) {
			filter.Insert(pred)
			preds = append(preds, quad.IRI(pred))
		}
	}

	p := cayley.StartPath(g.store, quad.IRI(nstr))
	if len(predicates) == 0 {
		p = p.OutWithTags([]string{"predicate"})
	} else {
		p = p.OutWithTags([]string{"predicate"}, preds...)
	}
	p = p.Tag("object")

	p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		// Check if this is actually a node and not a property
		if !isIRI(m["object"]) {
			properties = append(properties, &Property{
				Predicate: valToStr(m["predicate"]),
				Value:     valToStr(m["object"]),
			})
		}
	})

	// Given the Amass data model, valid nodes should always have at least
	// one property, and for that reason, it doesn't need to be checked here
	return properties, nil
}

// CountProperties implements the GraphDatabase interface.
func (g *CayleyGraph) CountProperties(node Node, predicates ...string) (int, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" || !g.nodeExists(nstr, "") {
		return 0, fmt.Errorf("%s: CountProperties: Invalid node reference argument", g.String())
	}

	var preds []interface{}
	filter := stringset.New()
	for _, pred := range predicates {
		if !filter.Has(pred) {
			filter.Insert(pred)
			preds = append(preds, quad.IRI(pred))
		}
	}

	p := cayley.StartPath(g.store, quad.IRI(nstr))
	if len(predicates) == 0 {
		p = p.Out()
	} else {
		p = p.Out(preds...)
	}

	var count int
	g.optimizedIterate(p, func(value quad.Value) {
		if !isIRI(value) {
			count++
		}
	})
	return count, nil
}

// DeleteProperty implements the GraphDatabase interface.
func (g *CayleyGraph) DeleteProperty(node Node, predicate, value string) error {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" || !g.nodeExists(nstr, "") {
		return fmt.Errorf("%s: DeleteProperty: Invalid node reference argument", g.String())
	}

	if !g.isBolt || !g.noSync {
		// Check if the property exists on the node
		p := cayley.StartPath(g.store, quad.IRI(nstr)).Has(quad.IRI(predicate), quad.String(value))
		if first := g.optimizedFirst(p); first == nil {
			return fmt.Errorf("%s: DeleteProperty: The property does not exist on node: %s", g.String(), nstr)
		}
	}

	return g.store.RemoveQuad(quad.Make(quad.IRI(nstr), quad.IRI(predicate), quad.String(value), nil))
}
