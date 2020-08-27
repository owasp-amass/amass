// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"errors"

	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/cayley/graph"
	"github.com/cayleygraph/cayley/writer"
	"github.com/cayleygraph/quad"
)

// MigrateEvents copies the nodes and edges related to the Events identified by the uuids from the receiver Graph into another.
func (g *Graph) MigrateEvents(to *Graph, uuids ...string) error {
	g.db.Lock()
	defer g.db.Unlock()

	var events []quad.Value
	for _, event := range uuids {
		events = append(events, quad.IRI(event))
	}

	var quads []quad.Quad
	var vals []quad.Value
	// Build quads for the events in scope
	p := cayley.StartPath(g.db.store, events...).Has(quad.IRI("type"), quad.String("event"))
	p = p.Tag("subject").OutWithTags([]string{"predicate"}).Tag("object")
	p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		vals = append(vals, m["object"])
		quads = append(quads, quad.Make(m["subject"], m["predicate"], m["object"], nil))
	})
	// Build quads for all nodes associated with the events in scope
	p = cayley.StartPath(g.db.store, vals...).Has(quad.IRI("type")).Unique()
	p = p.Tag("subject").OutWithTags([]string{"predicate"}).Tag("object")
	p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		quads = append(quads, quad.Make(m["subject"], m["predicate"], m["object"], nil))
	})

	opts := make(graph.Options)
	opts["ignore_missing"] = true
	opts["ignore_duplicate"] = true

	w, err := writer.NewSingleReplication(to.db.store, opts)
	if len(quads) > 0 {
		err = w.AddQuadSet(quads)
	}

	return err
}

// MigrateEventsInScope copies the nodes and edges related to the Events identified by the uuids from the receiver Graph into another.
func (g *Graph) MigrateEventsInScope(to *Graph, d []string) error {
	if len(d) == 0 {
		return errors.New("MigrateEventsInScope: No domain names provided")
	}

	var domains []quad.Value
	for _, domain := range d {
		domains = append(domains, quad.IRI(domain))
	}

	g.db.Lock()
	var uuids []string
	// Obtain the events that are in scope according to the domain name arguments
	p := cayley.StartPath(g.db.store).Has(quad.IRI("type"), quad.String("event")).Tag("event")
	p = p.Out(quad.IRI("domain")).Is(domains...).Back("event").Unique().Tag("uuid")
	p.Iterate(context.TODO()).TagValues(nil, func(m map[string]quad.Value) {
		uuids = append(uuids, valToStr(m["uuid"]))
	})
	g.db.Unlock()

	return g.MigrateEvents(to, uuids...)
}
