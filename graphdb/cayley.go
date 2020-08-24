// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graphdb

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/cayley/clog"
	"github.com/cayleygraph/cayley/graph"
	_ "github.com/cayleygraph/cayley/graph/kv/bolt" // Used by the cayley package
	"github.com/cayleygraph/quad"
)

// CayleyGraph is the object for managing a network infrastructure link graph.
type CayleyGraph struct {
	sync.Mutex
	store *cayley.Handle
	path  string
}

// NewCayleyGraph returns an intialized CayleyGraph object.
func NewCayleyGraph(path string, nosync bool) *CayleyGraph {
	var err error

	path = config.OutputDirectory(path)
	if path == "" {
		return nil
	}

	// If the directory does not yet exist, create it
	if err = os.MkdirAll(path, 0755); err != nil {
		return nil
	}

	if isNewFile(filepath.Join(path, "indexes.bolt")) {
		if err = graph.InitQuadStore("bolt", path, nil); err != nil {
			return nil
		}
	}

	clog.SetLogger(nil)
	opt := graph.Options{"nosync": true}
	if !nosync {
		opt = nil
	}

	store, err := cayley.NewGraph("bolt", path, opt)
	if err != nil {
		return nil
	}

	return &CayleyGraph{
		store: store,
		path:  path,
	}
}

// NewCayleyGraphMemory creates a temporary graph in memory.
func NewCayleyGraphMemory() *CayleyGraph {
	store, err := cayley.NewMemoryGraph()
	if err != nil {
		return nil
	}
	return &CayleyGraph{
		store: store,
		path:  "",
	}
}

func isNewFile(path string) bool {
	finfo, err := os.Stat(path)
	if os.IsNotExist(err) {
		return true
	}
	// See if the file is large enough to
	// be a previously initialized bolt file
	if finfo.Size() < 64 {
		return true
	}
	return false
}

// Close implements the GraphDatabase interface.
func (g *CayleyGraph) Close() {
	g.store.Close()
}

// String returns a description for the CayleyGraph object.
func (g *CayleyGraph) String() string {
	return "Cayley Graph"
}

// NodeToID implements the GraphDatabase interface.
func (g *CayleyGraph) NodeToID(n Node) string {
	var result string

	if n != nil {
		result = fmt.Sprintf("%s", n)
	}

	return result
}

// AllNodesOfType implements the GraphDatabase interface.
func (g *CayleyGraph) AllNodesOfType(ntypes ...string) ([]Node, error) {
	g.Lock()
	defer g.Unlock()

	var nodes []Node
	// Check if the request is for all nodes in the graph
	if len(ntypes) == 0 {
		p := cayley.StartPath(g.store)

		g.optimizedIterate(p, func(value quad.Value) {
			nodes = append(nodes, quad.ToString(value))
		})

		if len(nodes) == 0 {
			return nodes, fmt.Errorf("%s: AllNodesOfType: No nodes found", g.String())
		}

		return nodes, nil
	}

	filter := stringset.New()
	for _, ntype := range ntypes {
		p := cayley.StartPath(g.store).Has(quad.String("type"), quad.String(ntype))

		g.optimizedIterate(p, func(value quad.Value) {
			nstr := quad.ToString(value)

			if !filter.Has(nstr) {
				filter.Insert(nstr)
				nodes = append(nodes, nstr)
			}
		})
	}

	if len(nodes) == 0 {
		return nodes, fmt.Errorf("%s: AllNodesOfType: No nodes found", g.String())
	}

	return nodes, nil
}

// InsertNode implements the GraphDatabase interface.
func (g *CayleyGraph) InsertNode(id, ntype string) (Node, error) {
	g.Lock()
	defer g.Unlock()

	if id == "" || ntype == "" {
		return nil, fmt.Errorf("%s: InsertNode: Empty required arguments", g.String())
	}

	return id, g.store.AddQuad(quad.Make(id, "type", ntype, nil))
}

// ReadNode implements the GraphDatabase interface.
func (g *CayleyGraph) ReadNode(id, ntype string) (Node, error) {
	g.Lock()
	defer g.Unlock()

	if id == "" || ntype == "" {
		return nil, fmt.Errorf("%s: ReadNode: Empty required arguments", g.String())
	}

	// Check that a node with 'id' as a subject already exists
	p := cayley.StartPath(g.store, quad.String(id)).Has(quad.String("type"))
	if first := g.optimizedFirst(p); first != nil {
		return id, nil
	}

	return nil, fmt.Errorf("%s: ReadNode: Node %s does not exist", g.String(), id)
}

// DeleteNode implements the GraphDatabase interface.
func (g *CayleyGraph) DeleteNode(node Node) error {
	return g.removeAllNodeQuads(g.NodeToID(node))
}

func (g *CayleyGraph) removeAllNodeQuads(id string) error {
	g.Lock()
	defer g.Unlock()

	if id == "" {
		return fmt.Errorf("%s: removeAllNodeQuads: Empty node id provided", g.String())
	}

	// Check that a node with 'id' as a subject already exists
	p := cayley.StartPath(g.store, quad.String(id)).Has(quad.String("type"))
	if first := g.optimizedFirst(p); first == nil {
		return fmt.Errorf("%s: removeAllNodeQuads: Node %s does not exist", g.String(), id)
	}

	// Build the transaction that will perform the deletion
	t := cayley.NewTransaction()
	for _, predicate := range g.nodePredicates(id, "both") {
		path := cayley.StartPath(g.store, quad.String(id)).Both(quad.String(predicate))

		g.optimizedIterate(path, func(val quad.Value) {
			vstr := quad.ToString(val)

			t.RemoveQuad(quad.Make(id, predicate, vstr, nil))
		})
	}

	// Attempt to perform the deletion transaction
	return g.store.ApplyTransaction(t)
}

// InsertProperty implements the GraphDatabase interface.
func (g *CayleyGraph) InsertProperty(node Node, predicate, value string) error {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return fmt.Errorf("%s: InsertProperty: Invalid node reference argument", g.String())
	}

	return g.store.AddQuad(quad.Make(nstr, predicate, value, nil))
}

// ReadProperties implements the GraphDatabase interface.
func (g *CayleyGraph) ReadProperties(node Node, predicates ...string) ([]*Property, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	var properties []*Property

	if nstr == "" {
		return properties, fmt.Errorf("%s: ReadProperties: Invalid node reference argument", g.String())
	}

	preds := stringset.New(predicates...)
	for _, pred := range g.nodePredicates(nstr, "out") {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		vals := cayley.StartPath(g.store, quad.String(nstr)).Out(quad.String(pred))
		g.optimizedIterate(vals, func(value quad.Value) {
			vstr := quad.ToString(value)

			// Check if this is actually a node and not a property
			p := cayley.StartPath(g.store, quad.String(vstr)).Has(quad.String("type"))
			if first := g.optimizedFirst(p); first == nil {
				properties = append(properties, &Property{
					Predicate: pred,
					Value:     vstr,
				})
			}
		})
	}

	if len(properties) == 0 {
		return properties, fmt.Errorf("%s: ReadProperties: No properties discovered", g.String())
	}

	return properties, nil
}

// CountProperties implements the GraphDatabase interface.
func (g *CayleyGraph) CountProperties(node Node, predicates ...string) (int, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return 0, fmt.Errorf("%s: CountProperties: Invalid node reference argument", g.String())
	}

	var count int
	preds := stringset.New(predicates...)
	for _, pred := range g.nodePredicates(nstr, "out") {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		vals := cayley.StartPath(g.store, quad.String(nstr)).Out(quad.String(pred))
		g.optimizedIterate(vals, func(value quad.Value) {
			vstr := quad.ToString(value)

			// Check if this is actually a node and not a property
			p := cayley.StartPath(g.store, quad.String(vstr)).Has(quad.String("type"))
			if first := g.optimizedFirst(p); first == nil {
				count++
			}
		})
	}

	return count, nil
}

// DeleteProperty implements the GraphDatabase interface.
func (g *CayleyGraph) DeleteProperty(node Node, predicate, value string) error {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return fmt.Errorf("%s: DeleteProperty: Invalid node reference argument", g.String())
	}

	// Check if this is actually a node and not a property
	p := cayley.StartPath(g.store, quad.String(value)).Has(quad.String("type"))
	if first := g.optimizedFirst(p); first != nil {
		return fmt.Errorf("%s: DeleteProperty: Attempt to delete an edge as a property", g.String())
	}

	return g.store.RemoveQuad(quad.Make(nstr, predicate, value, nil))
}

// InsertEdge implements the GraphDatabase interface.
func (g *CayleyGraph) InsertEdge(edge *Edge) error {
	g.Lock()
	defer g.Unlock()

	nstr1 := g.NodeToID(edge.From)
	if nstr1 == "" {
		return fmt.Errorf("%s: InsertEdge: Invalid from node", g.String())
	}

	nstr2 := g.NodeToID(edge.To)
	if nstr2 == "" {
		return fmt.Errorf("%s: InsertEdge: Invalid to node", g.String())
	}

	return g.store.AddQuad(quad.Make(nstr1, edge.Predicate, nstr2, nil))
}

// ReadEdges implements the GraphDatabase interface.
func (g *CayleyGraph) ReadEdges(node Node, predicates ...string) ([]*Edge, error) {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadEdges: Invalid node reference argument", g.String())
	}

	var edges []*Edge
	if e, err := g.ReadInEdges(node, predicates...); err == nil {
		edges = append(edges, e...)
	}

	if e, err := g.ReadOutEdges(node, predicates...); err == nil {
		edges = append(edges, e...)
	}

	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadEdges: Failed to discover edges for the node %s", g.String(), nstr)
	}

	return edges, nil
}

// ReadInEdges implements the GraphDatabase interface.
func (g *CayleyGraph) ReadInEdges(node Node, predicates ...string) ([]*Edge, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadInEdges: Invalid node reference argument", g.String())
	}

	var edges []*Edge
	preds := stringset.New(predicates...)
	for _, pred := range g.nodePredicates(nstr, "in") {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		vals := cayley.StartPath(g.store, quad.String(nstr)).In(quad.String(pred)).Has(quad.String("type"))
		g.optimizedIterate(vals, func(value quad.Value) {
			edges = append(edges, &Edge{
				Predicate: pred,
				From:      quad.ToString(value),
				To:        node,
			})
		})
	}

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
	if nstr == "" {
		return 0, fmt.Errorf("%s: CountInEdges: Invalid node reference argument", g.String())
	}

	var preds []quad.Value
	for _, p := range predicates {
		preds = append(preds, quad.String(p))
	}

	p := cayley.StartPath(g.store, quad.String(nstr)).In(preds).Has(quad.String("type"))

	return g.optimizedCount(p), nil
}

// ReadOutEdges implements the GraphDatabase interface.
func (g *CayleyGraph) ReadOutEdges(node Node, predicates ...string) ([]*Edge, error) {
	g.Lock()
	defer g.Unlock()

	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadOutEdges: Invalid node reference argument", g.String())
	}

	var edges []*Edge
	preds := stringset.New(predicates...)
	for _, pred := range g.nodePredicates(nstr, "out") {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		vals := cayley.StartPath(g.store, quad.String(nstr)).Out(quad.String(pred)).Has(quad.String("type"))
		g.optimizedIterate(vals, func(value quad.Value) {
			edges = append(edges, &Edge{
				Predicate: pred,
				From:      node,
				To:        quad.ToString(value),
			})
		})
	}

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
	if nstr == "" {
		return 0, fmt.Errorf("%s: CountOutEdges: Invalid node reference argument", g.String())
	}

	var preds []quad.Value
	for _, p := range predicates {
		preds = append(preds, quad.String(p))
	}

	p := cayley.StartPath(g.store, quad.String(nstr)).Out(preds).Has(quad.String("type"))

	return g.optimizedCount(p), nil
}

// DeleteEdge implements the GraphDatabase interface.
func (g *CayleyGraph) DeleteEdge(edge *Edge) error {
	g.Lock()
	defer g.Unlock()

	from := g.NodeToID(edge.From)
	to := g.NodeToID(edge.To)
	if from == "" || to == "" {
		return fmt.Errorf("%s: DeleteEdge: Invalid edge reference argument", g.String())
	}

	return g.store.RemoveQuad(quad.Make(from, edge.Predicate, to, nil))
}

func (g *CayleyGraph) nodePredicates(id, direction string) []string {
	p := cayley.StartPath(g.store, quad.String(id))

	if direction == "in" {
		p = p.InPredicates()
	} else if direction == "out" {
		p = p.OutPredicates()
	}
	p = p.Unique()

	var predicates []string
	g.optimizedIterate(p, func(value quad.Value) {
		if vstr := quad.ToString(value); vstr != "" {
			predicates = append(predicates, vstr)
		}
	})

	return predicates
}

func (g *CayleyGraph) optimizedIterate(p *cayley.Path, callback func(value quad.Value)) {
	pb := p.Iterate(context.TODO())

	pb.Paths(false).EachValue(g.store, callback)
}

func (g *CayleyGraph) optimizedCount(p *cayley.Path) int {
	pb := p.Iterate(context.TODO())

	count, _ := pb.Paths(false).Count()

	return int(count)
}

func (g *CayleyGraph) optimizedFirst(p *cayley.Path) quad.Value {
	pb := p.Iterate(context.TODO())

	val, _ := pb.Paths(false).FirstValue(g.store)

	return val
}

// DumpGraph returns a string containing all data currently in the graph.
func (g *CayleyGraph) DumpGraph() string {
	g.Lock()
	defer g.Unlock()

	var result string
	p := cayley.StartPath(g.store).Has(quad.String("type")).Unique()
	g.optimizedIterate(p, func(node quad.Value) {
		label := quad.ToString(node)
		result += fmt.Sprintf("%s\n", label)

		for _, predicate := range g.nodePredicates(label, "out") {
			path := cayley.StartPath(g.store, quad.String(label)).Out(predicate)
			g.optimizedIterate(path, func(val quad.Value) {
				vstr := quad.ToString(val)

				result += fmt.Sprintf("\t%s: %s\n", predicate, vstr)
			})
		}
	})
	return result
}
