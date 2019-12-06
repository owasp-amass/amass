// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"errors"
	"time"

	"github.com/OWASP/Amass/v3/graph/db"
	"github.com/OWASP/Amass/v3/stringset"
	"golang.org/x/net/publicsuffix"
)

// InsertEvent create an event node in the graph that represents a discovery task.
func (g *Graph) InsertEvent(eventID string) (db.Node, error) {
	// Check if there is an existing start time for this event.
	// If not, then create the node and add the start time/date
	var finish string

	g.eventFinishLock.Lock()
	defer g.eventFinishLock.Unlock()

	eventNode, err := g.db.ReadNode(eventID)
	if err != nil {
		// Create a node to represent the event
		eventNode, err = g.db.InsertNode(eventID, "event")
		if err != nil {
			return eventNode, err
		}

		g.db.InsertProperty(eventNode, "start", time.Now().Format(time.RFC3339))
		if err != nil {
			return eventNode, err
		}
	} else {
		// Remove an existing 'finish' property
		var ok bool
		finish, ok = g.eventFinishes[eventID]
		if !ok {
			return eventNode, errors.New("Graph: InsertEvent: Event finish cache failure")
		}
		g.db.DeleteProperty(eventNode, "finish", finish)
	}

	finish = time.Now().Format(time.RFC3339)

	// Update the finish property with the current time/date
	g.db.InsertProperty(eventNode, "finish", finish)
	if err != nil {
		return eventNode, err
	}

	g.eventFinishes[eventID] = finish

	return eventNode, nil
}

// AddNodeToEvent creates an associations between a node in the graph, a data source and a discovery task.
func (g *Graph) AddNodeToEvent(node db.Node, source, tag, eventID string) error {
	if source == "" || tag == "" || eventID == "" {
		return errors.New("Graph: AddNodeToEvent: Invalid arguments provided")
	}

	eventNode, err := g.InsertEvent(eventID)
	if err != nil {
		return err
	}

	sourceNode, err := g.InsertSource(source, tag)
	if err != nil {
		return err
	}

	sourceEdge := &db.Edge{
		Predicate: "used",
		From:      eventNode,
		To:        sourceNode,
	}
	if err := g.InsertEdge(sourceEdge); err != nil {
		return err
	}

	eventEdge := &db.Edge{
		Predicate: source,
		From:      eventNode,
		To:        node,
	}
	if err := g.InsertEdge(eventEdge); err != nil {
		return err
	}

	return nil
}

func (g *Graph) inEventScope(node db.Node, uuid string) bool {
	edges, err := g.db.ReadInEdges(node)
	if err != nil {
		return false
	}

	for _, edge := range edges {
		if g.db.NodeToID(edge.From) == uuid {
			return true
		}
	}

	return false
}

// EventList returns a list of event UUIDs found in the graph.
func (g *Graph) EventList() []string {
	nodes, err := g.db.AllNodesOfType("event")
	if err != nil {
		return nil
	}

	ids := stringset.New()
	for _, node := range nodes {
		ids.Insert(g.db.NodeToID(node))
	}

	return ids.Slice()
}

// EventDomains returns the domains that were involved in the event.
func (g *Graph) EventDomains(uuid string) []string {
	names, err := g.db.AllNodesOfType("fqdn", uuid)
	if err != nil {
		return nil
	}

	domains := stringset.New()
	for _, name := range names {
		d, err := publicsuffix.EffectiveTLDPlusOne(g.db.NodeToID(name))

		if err == nil && d != "" {
			domains.Insert(d)
		}
	}

	return domains.Slice()
}

func (g *Graph) EventSubdomains(events ...string) []string {
	nodes, err := g.db.AllNodesOfType("fqdn", events...)
	if err != nil {
		return nil
	}

	var names []string
	for _, n := range nodes {
		d := g.db.NodeToID(n)
		etld, err := publicsuffix.EffectiveTLDPlusOne(d)
		if err != nil || etld == d {
			continue
		}

		names = append(names, g.db.NodeToID(n))
	}

	return names
}

// EventDateRange returns the date range associated with the provided event UUID.
func (g *Graph) EventDateRange(uuid string) (time.Time, time.Time) {
	var start, finish time.Time

	if event, err := g.db.ReadNode(uuid); err == nil {
		if properties, err := g.db.ReadProperties(event, "start", "finish"); err == nil {
			for _, p := range properties {
				if p.Predicate == "start" {
					start, _ = time.Parse(time.RFC3339, p.Value)
				} else {
					finish, _ = time.Parse(time.RFC3339, p.Value)
				}
			}
		}
	}

	return start, finish
}
