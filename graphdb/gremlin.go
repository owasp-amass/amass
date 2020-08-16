// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graphdb

import (
	"fmt"
	"sync"

	"github.com/OWASP/Amass/v3/stringset"
	"github.com/northwesternmutual/grammes"
)

// Gremlin is the client object for a Gremlin/TinkerPop graph database connection.
type Gremlin struct {
	sync.Mutex
	URL        string
	username   string
	password   string
	clientConn *grammes.Client
}

// NewGremlin returns a client object that implements the GraphDatabase interface.
// The url param typically looks like the following: ws://localhost:8182
func NewGremlin(url, user, pass string) *Gremlin {
	var err error

	g := &Gremlin{
		URL:      url,
		username: user,
		password: pass,
	}

	g.clientConn, err = g.getClient()
	if err != nil {
		return nil
	}
	return g
}

func (g *Gremlin) getClient() (*grammes.Client, error) {
	if g.username != "" && g.password != "" {
		return grammes.DialWithWebSocket(g.URL,
			grammes.WithMaxConcurrentMessages(10),
			grammes.WithAuthUserPass(g.username, g.password))
	}

	return grammes.DialWithWebSocket(g.URL,
		grammes.WithMaxConcurrentMessages(10))
}

func (g *Gremlin) client() *grammes.Client {
	g.Lock()
	defer g.Unlock()

	var err error
	if g.clientConn == nil || g.clientConn.IsBroken() {
		g.clientConn, err = g.getClient()
		fmt.Printf("%v\n", err)
	}

	return g.clientConn
}

// Close implements the GraphDatabase interface.
func (g *Gremlin) Close() {
	if g.clientConn == nil {
		return
	}

	g.clientConn.Close()
}

// String returns a description for the Gremlin client object.
func (g *Gremlin) String() string {
	return "Gremlin TinkerPop"
}

// NodeToID implements the GraphDatabase interface.
func (g *Gremlin) NodeToID(n Node) string {
	return fmt.Sprintf("%s", n)
}

// AllNodesOfType implements the GraphDatabase interface.
func (g *Gremlin) AllNodesOfType(ntypes ...string) ([]Node, error) {
	var err error
	var vertices []grammes.Vertex

	client := g.client()
	if client == nil {
		return nil, fmt.Errorf("%s: AllNodesOfType: Failed to obtain the client connection", g.String())
	}

	if len(ntypes) == 0 {
		vertices, err = client.AllVertices()

		if err != nil {
			return nil, fmt.Errorf("%s: AllNodesOfType: No nodes found", g.String())
		}
	} else {
		filter := stringset.New()

		for _, ntype := range ntypes {
			v, err := client.Vertices(ntype, "type", ntype)
			if err != nil {
				continue
			}

			for _, vertex := range v {
				nstr := vertex.PropertyValue("name", 0).(string)

				if !filter.Has(nstr) {
					filter.Insert(nstr)
					vertices = append(vertices, vertex)
				}
			}
		}
	}

	if len(vertices) == 0 {
		return nil, fmt.Errorf("%s: AllNodesOfType: No nodes found", g.String())
	}

	var nodes []Node
	for _, vertex := range vertices {
		nodes = append(nodes, vertex.PropertyValue("name", 0))
	}

	return nodes, nil
}

// InsertNode implements the GraphDatabase interface.
func (g *Gremlin) InsertNode(id, ntype string) (Node, error) {
	if id == "" || ntype == "" {
		return nil, fmt.Errorf("%s: InsertNode: Empty required arguments", g.String())
	}

	client := g.client()
	if client == nil {
		return nil, fmt.Errorf("%s: InsertNode: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	_, err := client.AddVertexByQuery(t.AddV(ntype).Property("name", id).Property("type", ntype))
	if err != nil {
		return nil, fmt.Errorf("%s: InsertNode: Failed to create node: %v", g.String(), err)
	}

	return id, nil
}

// ReadNode implements the GraphDatabase interface.
func (g *Gremlin) ReadNode(id, ntype string) (Node, error) {
	if id == "" {
		return nil, fmt.Errorf("%s: ReadNode: Invalid node provided", g.String())
	}

	client := g.client()
	if client == nil {
		return nil, fmt.Errorf("%s: ReadNode: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	vertices, err := client.VerticesByQuery(t.V().HasLabel(ntype).Has("name", id).Has("type", ntype))
	if err != nil || len(vertices) == 0 {
		return nil, fmt.Errorf("%s: ReadNode: Node %s does not exist: %v", g.String(), id, err)
	}

	return id, nil
}

// DeleteNode implements the GraphDatabase interface.
func (g *Gremlin) DeleteNode(node Node) error {
	id := g.NodeToID(node)
	if id == "" {
		return fmt.Errorf("%s: DeleteNode: Invalid node provided", g.String())
	}

	client := g.client()
	if client == nil {
		return fmt.Errorf("%s: DeleteNode: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	err := client.DropVerticesByQuery(t.V().Has("name", id).Drop())
	if err != nil {
		return fmt.Errorf("%s: DeleteNode: Node %s could not be deleted: %v", g.String(), id, err)
	}

	return nil
}

// InsertProperty implements the GraphDatabase interface.
func (g *Gremlin) InsertProperty(node Node, predicate, value string) error {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return fmt.Errorf("%s: InsertProperty: Invalid node reference argument", g.String())
	}

	client := g.client()
	if client == nil {
		return fmt.Errorf("%s: InsertProperty: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	vertices, err := client.VerticesByQuery(t.V().Has("name", nstr))
	if err != nil || len(vertices) == 0 {
		return fmt.Errorf("%s: InsertProperty: Node %s does not exist: %v", g.String(), nstr, err)
	}

	err = vertices[0].AddProperty(client, predicate, value)
	if err != nil {
		return fmt.Errorf("%s: InsertProperty: Failed to add the property for node %s: %v", g.String(), nstr, err)
	}

	return nil
}

// ReadProperties implements the GraphDatabase interface.
func (g *Gremlin) ReadProperties(node Node, predicates ...string) ([]*Property, error) {
	nstr := g.NodeToID(node)
	var properties []*Property

	if nstr == "" {
		return properties, fmt.Errorf("%s: ReadProperties: Invalid node reference argument", g.String())
	}

	client := g.client()
	if client == nil {
		return properties, fmt.Errorf("%s: ReadProperties: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	vertices, err := client.VerticesByQuery(t.V().Has("name", nstr))
	if err != nil || len(vertices) == 0 {
		return properties, fmt.Errorf("%s: ReadProperties: Node %s does not exist: %v", g.String(), nstr, err)
	}

	preds := stringset.New(predicates...)
	for pred, val := range vertices[0].Value.Properties {
		if len(predicates) > 0 && !preds.Has(pred) {
			continue
		}

		properties = append(properties, &Property{
			Predicate: pred,
			Value:     val[0].Value.Value.Value.(string),
		})
	}

	if len(properties) == 0 {
		return properties, fmt.Errorf("%s: ReadProperties: No properties discovered", g.String())
	}

	return properties, nil
}

// CountProperties implements the GraphDatabase interface.
func (g *Gremlin) CountProperties(node Node, predicates ...string) (int, error) {
	properties, err := g.ReadProperties(node, predicates...)
	if err != nil {
		return 0, fmt.Errorf("%s: CountProperties: Failed to obtain the properties: %v", g.String(), err)
	}

	return len(properties), nil
}

// DeleteProperty implements the GraphDatabase interface.
func (g *Gremlin) DeleteProperty(node Node, predicate, value string) error {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return fmt.Errorf("%s: DeleteProperty: Invalid node reference argument", g.String())
	}

	client := g.client()
	if client == nil {
		return fmt.Errorf("%s: DeleteProperty: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	vertices, err := client.VerticesByQuery(t.V().Has("name", nstr))
	if err != nil || len(vertices) == 0 {
		return fmt.Errorf("%s: DeleteProperty: Node %s does not exist: %v", g.String(), nstr, err)
	}

	err = vertices[0].DropProperties(client, predicate)
	if err != nil {
		return fmt.Errorf("%s: DeleteProperty: Failed to delete property %s for node %s: %v", g.String(), predicate, nstr, err)
	}

	return nil
}

// InsertEdge implements the GraphDatabase interface.
func (g *Gremlin) InsertEdge(edge *Edge) error {
	from := g.NodeToID(edge.From)
	to := g.NodeToID(edge.To)
	if from == "" || to == "" {
		return fmt.Errorf("%s: InsertEdge: Invalid edge argument", g.String())
	}

	client := g.client()
	if client == nil {
		return fmt.Errorf("%s: InsertEdge: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	vertices, err := client.VerticesByQuery(t.V().Has("name", from))
	if err != nil || len(vertices) == 0 {
		return fmt.Errorf("%s: InsertEdge: Node %s does not exist: %v", g.String(), from, err)
	}
	vertex1 := vertices[0]

	vertices, err = client.VerticesByQuery(t.V().Has("name", to))
	if err != nil || len(vertices) == 0 {
		return fmt.Errorf("%s: InsertEdge: Node %s does not exist: %v", g.String(), to, err)
	}
	vertex2 := vertices[0]

	_, err = vertex1.AddEdge(client, edge.Predicate, vertex2.ID())
	if err != nil {
		return fmt.Errorf("%s: InsertEdge: Failed to create edge between Node %s and Node %s: %v", g.String(), from, to, err)
	}

	return nil
}

// ReadEdges implements the GraphDatabase interface.
func (g *Gremlin) ReadEdges(node Node, predicates ...string) ([]*Edge, error) {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadEdges: Invalid node reference argument", g.String())
	}

	gEdges, err := g.vertexEdges(node, BOTH, predicates...)
	if err != nil {
		return nil, fmt.Errorf("%s: ReadEdges: %v", g.String(), err)
	}

	edges := g.convertEdges(gEdges)
	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadEdges: Failed to discover edges for node %s", g.String(), nstr)
	}

	return edges, nil
}

// ReadInEdges implements the GraphDatabase interface.
func (g *Gremlin) ReadInEdges(node Node, predicates ...string) ([]*Edge, error) {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadInEdges: Invalid node reference argument", g.String())
	}

	gEdges, err := g.vertexEdges(node, IN, predicates...)
	if err != nil {
		return nil, fmt.Errorf("%s: ReadInEdges: %v", g.String(), err)
	}

	edges := g.convertEdges(gEdges)
	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadInEdges: Failed to discover edges coming into node %s", g.String(), nstr)
	}

	return edges, nil
}

// CountInEdges implements the GraphDatabase interface.
func (g *Gremlin) CountInEdges(node Node, predicates ...string) (int, error) {
	edges, err := g.vertexEdges(node, IN, predicates...)
	if err != nil {
		return 0, fmt.Errorf("%s: CountInEdges: %v", g.String(), err)
	}

	return len(edges), nil
}

// ReadOutEdges implements the GraphDatabase interface.
func (g *Gremlin) ReadOutEdges(node Node, predicates ...string) ([]*Edge, error) {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: ReadOutEdges: Invalid node reference argument", g.String())
	}

	gEdges, err := g.vertexEdges(node, OUT, predicates...)
	if err != nil {
		return nil, fmt.Errorf("%s: ReadOutEdges: %v", g.String(), err)
	}

	edges := g.convertEdges(gEdges)
	if len(edges) == 0 {
		return nil, fmt.Errorf("%s: ReadOutEdges: Failed to discover out-edges from node %s", g.String(), nstr)
	}

	return edges, nil
}

// CountOutEdges implements the GraphDatabase interface.
func (g *Gremlin) CountOutEdges(node Node, predicates ...string) (int, error) {
	edges, err := g.vertexEdges(node, OUT, predicates...)
	if err != nil {
		return 0, fmt.Errorf("%s: CountOutEdges: %v", g.String(), err)
	}

	return len(edges), nil
}

func (g *Gremlin) vertexEdges(node Node, direction int, predicates ...string) ([]grammes.Edge, error) {
	nstr := g.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("Invalid node reference argument")
	}

	client := g.client()
	if client == nil {
		return nil, fmt.Errorf("Failed to obtain the client connection")
	}

	t := grammes.Traversal()

	vertices, err := client.VerticesByQuery(t.V().Has("name", nstr))
	if err != nil || len(vertices) == 0 {
		return nil, fmt.Errorf("Node %s does not exist: %v", nstr, err)
	}

	var edges []grammes.Edge
	switch direction {
	case IN:
		edges, err = vertices[0].QueryInEdges(client, predicates...)
	case OUT:
		edges, err = vertices[0].QueryOutEdges(client, predicates...)
	case BOTH:
		edges, err = vertices[0].QueryBothEdges(client, predicates...)
	}

	if err != nil {
		return nil, fmt.Errorf("Failed to obtain edges for Node %s: %v", nstr, err)
	}

	return edges, nil
}

// DeleteEdge implements the GraphDatabase interface.
func (g *Gremlin) DeleteEdge(edge *Edge) error {
	from := g.NodeToID(edge.From)
	to := g.NodeToID(edge.To)
	if from == "" || to == "" {
		return fmt.Errorf("%s: DeleteEdge: Invalid edge reference argument", g.String())
	}

	client := g.client()
	if client == nil {
		return fmt.Errorf("%s: DeleteEdge: Failed to obtain the client connection", g.String())
	}

	t := grammes.Traversal()

	vertices, err := client.VerticesByQuery(t.V().Has("name", from))
	if err != nil || len(vertices) == 0 {
		return fmt.Errorf("%s: DeleteEdge: Node %s does not exist: %v", g.String(), from, err)
	}
	vertex1 := vertices[0]

	vertices, err = client.VerticesByQuery(t.V().Has("name", to))
	if err != nil || len(vertices) == 0 {
		return fmt.Errorf("%s: DeleteEdge: Node %s does not exist: %v", g.String(), to, err)
	}
	vertex2 := vertices[0]

	_, err = client.ExecuteQuery(t.V(int(vertex1.ID())).BothE(
		edge.Predicate).Where(t.OtherV().HasID(int(vertex2.ID()))).Drop())
	return err
}

// DumpGraph returns a string containing all data currently in the graph.
func (g *Gremlin) DumpGraph() string {
	return ""
}

func (g *Gremlin) convertEdges(e []grammes.Edge) []*Edge {
	var edges []*Edge

	client := g.client()
	if client == nil {
		return edges
	}

	for _, edge := range e {
		v1, err := edge.QueryOutVertex(client)
		if err != nil {
			continue
		}
		v1props := v1.PropertyMap()

		v1Prop := v1props["name"]
		if len(v1Prop) == 0 {
			continue
		}
		v1Name := v1Prop[0].GetValue()

		v2, err := edge.QueryInVertex(client)
		if err != nil {
			continue
		}
		v2props := v2.PropertyMap()

		v2Prop := v2props["name"]
		if len(v2Prop) == 0 {
			continue
		}
		v2Name := v2Prop[0].GetValue()

		edges = append(edges, &Edge{
			Predicate: edge.Label(),
			From:      v1Name,
			To:        v2Name,
		})
	}

	return edges
}
