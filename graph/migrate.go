// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"fmt"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/graphdb"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/semaphore"
)

const maxConcurrentDBRequests int = 3

// MigrateEvent copies the nodes and edges related to the Event identified by the uuid from the receiver Graph into another.
func (g *Graph) MigrateEvent(uuid string, to *Graph) error {
	q := new(queue.Queue)
	sem := semaphore.NewSimpleSemaphore(maxConcurrentDBRequests)

	idToNode, err := newNodeMap(uuid, g, to)
	if err != nil {
		return fmt.Errorf("Graph: Migrate: Failed to setup the node map: %v", err)
	}

	event, err := g.db.ReadNode(uuid, "event")
	if err != nil {
		return fmt.Errorf("Graph: Migrate: Failed to read the event node for %s: %v", uuid, err)
	}

	if _, _, err := idToNode.getNode(uuid, event); err != nil {
		return fmt.Errorf("Graph: Migrate: %v", err)
	}

	q.Append(event)
	for {
		element, ok := q.Next()
		if !ok {
			break
		}
		cur := element.(graphdb.Node)

		curID := g.db.NodeToID(cur)
		// Get the same node that is in the graph receiving the copies
		tocur, found, err := idToNode.getNode(curID, cur)
		if err != nil || !found {
			return fmt.Errorf("Graph: Migrate: Failed to read the node %s", curID)
		}

		edges, err := g.db.ReadOutEdges(cur)
		if err != nil {
			continue
		}

		elen := len(edges)
		ch := make(chan error, elen)
		for _, edge := range edges {
			sem.Acquire(1)
			go g.migrateEdge(tocur, edge, to, q, idToNode, sem, ch)
		}
		// Wait for all error values from edge migrations
		for i := 0; i < elen; i++ {
			if err := <-ch; err != nil {
				return err
			}
		}
	}

	return nil
}

func (g *Graph) migrateEdge(cur graphdb.Node, edge *graphdb.Edge, to *Graph,
	q *queue.Queue, ids *nodeMap, sem semaphore.Semaphore, ch chan error) {
	defer sem.Release(1)

	node, found, err := ids.getNode(g.db.NodeToID(edge.To), edge.To)
	if err != nil {
		if err.Error() == "out of scope" {
			err = nil
		}
		ch <- err
		return
	}

	if !found {
		q.Append(edge.To)
	}

	for i := 0; i < 3; i++ {
		err = to.InsertEdge(&graphdb.Edge{
			Predicate: edge.Predicate,
			From:      cur,
			To:        node,
		})
		if err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	ch <- err
}

func (g *Graph) migrateNode(node graphdb.Node, to *Graph) (graphdb.Node, error) {
	id := g.db.NodeToID(node)
	if id == "" {
		return nil, fmt.Errorf("migrateNode: Invalid %s node provided", g.String())
	}

	// Obtain the properties of the Node being migrated
	properties, err := g.db.ReadProperties(node)
	if err != nil || len(properties) == 0 {
		return nil, fmt.Errorf("migrateNode: Properties for the %s node %s could not be obtained: %v", g.String(), id, err)
	}

	// Obtain the type of the Node being migrated
	ntype := getTypeFromProperties(properties)
	if ntype == "" {
		return nil, fmt.Errorf("migrateNode: Unable to obtain the type for the %s node %s: %v", g.String(), id, err)
	}

	// Check if this node already exists in the 'to' graph
	tonode, err := to.db.ReadNode(id, ntype)
	if err == nil {
		return tonode, nil
	}

	// Create the Node in the Graph
	tonode, err = to.db.InsertNode(id, ntype)
	if err != nil {
		return nil, fmt.Errorf("migrateNode: Failed to insert the %s node %s: %v", g.String(), id, err)
	}

	// Copy all the properties into the Node being migrated
	if err := g.migrateProperties(tonode, properties, to); err != nil {
		return nil, fmt.Errorf("migrateNode: Failed to migrate properties for the %s node %s: %v", g.String(), id, err)
	}

	return tonode, nil
}

func (g *Graph) nodeToType(node graphdb.Node) string {
	// Obtain the properties of the Node being migrated
	properties, err := g.db.ReadProperties(node)
	if err != nil || len(properties) == 0 {
		return ""
	}

	// Obtain the type of the Node being migrated
	return getTypeFromProperties(properties)
}

func (g *Graph) migrateProperties(node graphdb.Node, properties []*graphdb.Property, to *Graph) error {
	for _, p := range properties {
		if p.Predicate == "type" {
			continue
		}

		if err := to.db.InsertProperty(node, p.Predicate, p.Value); err != nil {
			return err
		}
	}

	return nil
}

func getTypeFromProperties(properties []*graphdb.Property) string {
	var ntype string

	for _, p := range properties {
		if p.Predicate == "type" {
			ntype = p.Value
			break
		}
	}

	return ntype
}

type nodeMap struct {
	sync.Mutex
	uuid     string
	from, to *Graph
	nodes    map[string]graphdb.Node
}

func newNodeMap(uuid string, from, to *Graph) (*nodeMap, error) {
	// Setup the Event associated with the UUID to start the migration
	event, err := from.db.ReadNode(uuid, "event")
	if err != nil {
		return nil, err
	}

	m := &nodeMap{
		uuid:  uuid,
		from:  from,
		to:    to,
		nodes: make(map[string]graphdb.Node),
	}

	node, err := from.migrateNode(event, to)
	if err != nil {
		return nil, err
	}
	m.nodes[uuid] = node

	return m, nil
}

func (n *nodeMap) getNode(id string, fromNode graphdb.Node) (graphdb.Node, bool, error) {
	n.Lock()
	defer n.Unlock()

	node, found := n.nodes[id]
	if found {
		return node, found, nil
	}

	if !n.from.InEventScope(fromNode, n.uuid) {
		return nil, false, fmt.Errorf("out of scope")
	}

	var err error
	for i := 0; i < 3; i++ {
		node, err = n.from.migrateNode(fromNode, n.to)
		if err == nil {
			n.nodes[id] = node
			break
		}
		time.Sleep(time.Second)
	}

	return node, false, err
}
