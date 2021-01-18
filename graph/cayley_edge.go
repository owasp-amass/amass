// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"fmt"

	"github.com/caffix/stringset"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
)

// Constant values that represent the direction of edges during graph queries.
const (
	IN int = iota
	OUT
	BOTH
)

// Edge represents an edge in the graph.
type Edge struct {
	Predicate string
	From, To  Node
}

// InsertEdge implements the GraphDatabase interface.
func (g *CayleyGraph) InsertEdge(edge *Edge) error {
	g.Lock()
	defer g.Unlock()

	if edge.Predicate == "" {
		return fmt.Errorf("%s: InsertEdge: Empty edge predicate", g.String())
	}
	nstr1 := g.NodeToID(edge.From)
	if nstr1 == "" || !g.nodeExists(nstr1, "") {
		return fmt.Errorf("%s: InsertEdge: Invalid from node", g.String())
	}
	nstr2 := g.NodeToID(edge.To)
	if nstr2 == "" || !g.nodeExists(nstr2, "") {
		return fmt.Errorf("%s: InsertEdge: Invalid to node", g.String())
	}
	if !g.isBolt || !g.noSync {
		// Check if this edge has already been inserted
		p := cayley.StartPath(g.store, quad.IRI(nstr1)).Out(quad.IRI(edge.Predicate)).Is(quad.IRI(nstr2))
		if first, err := p.Iterate(context.Background()).FirstValue(nil); err == nil && first != nil {
			return nil
		}
	}

	return g.store.AddQuad(quad.Make(quad.IRI(nstr1), quad.IRI(edge.Predicate), quad.IRI(nstr2), nil))
}

// ReadEdges implements the GraphDatabase interface.
func (g *CayleyGraph) ReadEdges(node Node, predicates ...string) ([]*Edge, error) {
	var edges []*Edge

	if e, err := g.ReadInEdges(node, predicates...); err == nil {
		edges = append(edges, e...)
	}

	if e, err := g.ReadOutEdges(node, predicates...); err == nil {
		edges = append(edges, e...)
	}

	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadEdges: Failed to discover edges for the node %s", g.String(), g.NodeToID(node))
	}

	return edges, nil
}

// CountEdges counts the total number of edges to a node.
func (g *CayleyGraph) CountEdges(node Node, predicates ...string) (int, error) {
	var count int

	if c, err := g.CountInEdges(node, predicates...); err == nil {
		count += c
	} else {
		return 0, fmt.Errorf("%s: CountEdges: %v", g.String(), err)
	}

	if c, err := g.CountOutEdges(node, predicates...); err == nil {
		count += c
	}

	return count, nil
}

// ReadInEdges implements the GraphDatabase interface.
func (g *CayleyGraph) ReadInEdges(node Node, predicates ...string) ([]*Edge, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" || !g.nodeExists(nstr, "") {
		return nil, fmt.Errorf("%s: ReadInEdges: Invalid node reference argument", g.String())
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
		p = p.InWithTags([]string{"predicate"})
	} else {
		p = p.InWithTags([]string{"predicate"}, preds...)
	}
	p = p.Has(quad.IRI("type")).Tag("object")

	var edges []*Edge
	p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		edges = append(edges, &Edge{
			Predicate: valToStr(m["predicate"]),
			From:      valToStr(m["object"]),
			To:        node,
		})
	})

	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadInEdges: Failed to discover edges coming into the node %s", g.String(), nstr)
	}
	return edges, nil
}

// CountInEdges implements the GraphDatabase interface.
func (g *CayleyGraph) CountInEdges(node Node, predicates ...string) (int, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" || !g.nodeExists(nstr, "") {
		return 0, fmt.Errorf("%s: CountInEdges: Invalid node reference argument", g.String())
	}

	p := cayley.StartPath(g.store, quad.IRI(nstr))
	if len(predicates) == 0 {
		p = p.In()
	} else {
		p = p.In(strsToVals(predicates...))
	}
	p = p.Has(quad.IRI("type"))
	count, err := p.Iterate(context.Background()).Count()

	return int(count), err
}

// ReadOutEdges implements the GraphDatabase interface.
func (g *CayleyGraph) ReadOutEdges(node Node, predicates ...string) ([]*Edge, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" || !g.nodeExists(nstr, "") {
		return nil, fmt.Errorf("%s: ReadOutEdges: Invalid node reference argument", g.String())
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
	p = p.Has(quad.IRI("type")).Tag("object")

	var edges []*Edge
	p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		edges = append(edges, &Edge{
			Predicate: valToStr(m["predicate"]),
			From:      node,
			To:        valToStr(m["object"]),
		})
	})

	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadOutEdges: Failed to discover edges leaving the node %s", g.String(), nstr)
	}
	return edges, nil
}

// CountOutEdges implements the GraphDatabase interface.
func (g *CayleyGraph) CountOutEdges(node Node, predicates ...string) (int, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" || !g.nodeExists(nstr, "") {
		return 0, fmt.Errorf("%s: CountOutEdges: Invalid node reference argument", g.String())
	}

	p := cayley.StartPath(g.store, quad.IRI(nstr))
	if len(predicates) == 0 {
		p = p.Out()
	} else {
		p = p.Out(strsToVals(predicates...))
	}
	p = p.Has(quad.IRI("type"))
	count, err := p.Iterate(context.Background()).Count()

	return int(count), err
}

// DeleteEdge implements the GraphDatabase interface.
func (g *CayleyGraph) DeleteEdge(edge *Edge) error {
	g.Lock()
	defer g.Unlock()

	from := g.NodeToID(edge.From)
	to := g.NodeToID(edge.To)
	if from == "" || !g.nodeExists(from, "") || to == "" || !g.nodeExists(to, "") {
		return fmt.Errorf("%s: DeleteEdge: Invalid edge reference argument", g.String())
	}

	// Check if the edge exists
	p := cayley.StartPath(g.store, quad.IRI(from)).Out(quad.IRI(edge.Predicate)).Is(quad.IRI(to))
	if first, err := p.Iterate(context.Background()).FirstValue(nil); err != nil || first == nil {
		return fmt.Errorf("%s: DeleteEdge: The edge does not exist", g.String())
	}

	return g.store.RemoveQuad(quad.Make(quad.IRI(from), quad.IRI(edge.Predicate), quad.IRI(to), nil))
}
