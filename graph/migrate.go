// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"errors"

	"github.com/OWASP/Amass/v3/graphdb"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/stringset"
)

// Migrate copies the nodes and edges related to the Event identified by the uuid from the receiver Graph into another.
func (g *Graph) Migrate(uuid string, to *Graph) error {
	q := new(queue.Queue)
	ids := stringset.New()

	// Setup the Event associated with the UUID to start the migration
	event, err := g.db.ReadNode(uuid, "event")
	if err != nil {
		return err
	}

	toevent, newevent := g.migrateNode(event, ids, to)
	if toevent == nil || newevent == false {
		return errors.New("Graph: Migrate: Failed to migrate the event")
	}

	q.Append(event)
	for {
		element, ok := q.Next()
		if !ok {
			break
		}
		cur := element.(graphdb.Node)

		// Obtain the type for the node currently being worked on
		ntype := g.nodeToType(cur)
		if ntype == "" {
			continue
		}

		// Get the same node in the graph receiving the copies
		tocur, err := to.db.ReadNode(g.db.NodeToID(cur), ntype)
		if err != nil {
			continue
		}

		edges, err := g.db.ReadOutEdges(cur)
		if err != nil {
			continue
		}

		for _, edge := range edges {
			if !g.InEventScope(edge.To, uuid) {
				continue
			}

			node, newnode := g.migrateNode(edge.To, ids, to)
			if node == nil {
				continue
			}

			to.db.InsertEdge(&graphdb.Edge{
				Predicate: edge.Predicate,
				From:      tocur,
				To:        node,
			})

			if newnode {
				q.Append(edge.To)
			}
		}
	}

	return nil
}

func (g *Graph) migrateNode(node graphdb.Node, ids stringset.Set, to *Graph) (graphdb.Node, bool) {
	id := g.db.NodeToID(node)
	if id == "" {
		return nil, false
	}

	// Obtain the properties of the Node being migrated
	properties, err := g.db.ReadProperties(node)
	if err != nil || len(properties) == 0 {
		return nil, false
	}

	// Obtain the type of the Node being migrated
	ntype := g.getTypeFromProperties(properties)
	if ntype == "" {
		return nil, false
	}

	// Check that this Node has not already been created in the Graph
	if ids.Has(id) {
		if tonode, err := to.db.ReadNode(id, ntype); err == nil {
			return tonode, false
		}
		return nil, false
	}
	ids.Insert(id)

	// Create the Node in the Graph
	tonode, err := to.db.InsertNode(id, ntype)
	if err != nil {
		return nil, false
	}

	// Copy all the properties into the Node being migrated
	if err := g.migrateProperties(tonode, properties, to); err != nil {
		return nil, false
	}

	return tonode, true
}

func (g *Graph) nodeToType(node graphdb.Node) string {
	// Obtain the properties of the Node being migrated
	properties, err := g.db.ReadProperties(node)
	if err != nil || len(properties) == 0 {
		return ""
	}

	// Obtain the type of the Node being migrated
	return g.getTypeFromProperties(properties)
}

func (g *Graph) getTypeFromProperties(properties []*graphdb.Property) string {
	var ntype string

	for _, p := range properties {
		if p.Predicate == "type" {
			ntype = p.Value
			break
		}
	}

	return ntype
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
