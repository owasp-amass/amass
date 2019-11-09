// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"errors"
	"fmt"

	"github.com/OWASP/Amass/v3/stringset"
)

// InsertSource creates a data source node in the graph.
func (g *Graph) InsertSource(source, tag string) error {
	node, err := g.db.ReadNode(source)
	if err != nil {
		// Create a node to represent the source
		node, err = g.db.InsertNode(source, "source")
		if err != nil {
			return err
		}
	}

	var insert bool
	if p, err := g.db.ReadProperties(node, "tag"); err == nil && len(p) > 0 {
		if p[0].Value != tag {
			// Remove an existing 'tag' property
			g.db.DeleteProperty(node, p[0].Predicate, p[0].Value)
			// Update the 'tag' property
			insert = true
		}
	} else {
		// The tag was not found
		insert = true
	}

	if insert {
		if err := g.db.InsertProperty(node, "tag", tag); err != nil {
			return err
		}
	}

	return nil
}

// SourceTag returns the tag associated with the identified data source.
func (g *Graph) SourceTag(source string) string {
	if source == "" {
		return ""
	}

	node, err := g.db.ReadNode(source)
	if err != nil {
		return ""
	}

	if p, err := g.db.ReadProperties(node, "tag"); err == nil && len(p) > 0 {
		return p[0].Value
	}

	return ""
}

// NodeSourcesDuringEvent returns the names of data sources that
// provided the identified node during the event.
func (g *Graph) NodeSourcesDuringEvent(id, eventID string) ([]string, error) {
	if id == "" || eventID == "" {
		return nil, errors.New("Graph: NodeSourcesDuringEvent: Invalid IDs provided")
	}

	if err := g.InsertEvent(eventID); err != nil {
		return nil, err
	}

	eventNode, err := g.db.ReadNode(eventID)
	if err != nil {
		return nil, err
	}

	edges, err := g.db.ReadOutEdges(eventNode)
	if err != nil {
		return nil, err
	}

	var sources []string
	filter := stringset.New()

	for _, edge := range edges {
		if toID := g.db.NodeToID(edge.To); toID == id {
			if !filter.Has(edge.Predicate) {
				filter.Insert(edge.Predicate)
				sources = append(sources, edge.Predicate)
			}
		}
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("No data sources found for node %s during event %s", id, eventID)
	}

	return sources, nil
}
