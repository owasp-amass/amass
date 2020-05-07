// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"fmt"

	"github.com/OWASP/Amass/v3/graphdb"
	"github.com/OWASP/Amass/v3/stringset"
)

var notDataSourceSet = stringset.New("tld", "root", "domain",
	"cname_record", "ptr_record", "mx_record", "ns_record", "srv_record", "service")

// InsertSource creates a data source node in the graph.
func (g *Graph) InsertSource(source, tag string) (graphdb.Node, error) {
	node, err := g.InsertNodeIfNotExist(source, "source")
	if err != nil {
		return node, err
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
			return node, err
		}
	}

	return node, nil
}

// SourceTag returns the tag associated with the identified data source.
func (g *Graph) SourceTag(source string) string {
	if source == "" {
		return ""
	}

	node, err := g.db.ReadNode(source, "source")
	if err != nil {
		return ""
	}

	if p, err := g.db.ReadProperties(node, "tag"); err == nil && len(p) > 0 {
		return p[0].Value
	}

	return ""
}

// NodeSources returns the names of data sources that identified the Node parameter during the events.
func (g *Graph) NodeSources(node graphdb.Node, events ...string) ([]string, error) {
	nstr := g.db.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: NodeSources: Invalid node reference argument", g.String())
	}

	allevents, err := g.AllNodesOfType("event", events...)
	if err != nil {
		return nil, fmt.Errorf("%s: NodeSources: Failed to obtain the list of events", g.String())
	}

	eventset := stringset.New()
	for _, event := range allevents {
		if estr := g.db.NodeToID(event); estr != "" {
			eventset.Insert(estr)
		}
	}

	edges, err := g.db.ReadInEdges(node)
	if err != nil {
		return nil, fmt.Errorf("%s: NodeSources: Failed to obtain the list of in-edges: %v", g.String(), err)
	}

	var sources []string
	filter := stringset.New()
	for _, edge := range edges {
		if notDataSourceSet.Has(edge.Predicate) {
			continue
		}

		if name := g.db.NodeToID(edge.From); eventset.Has(name) && !filter.Has(edge.Predicate) {
			filter.Insert(edge.Predicate)
			sources = append(sources, edge.Predicate)
		}
	}

	if len(sources) == 0 {
		return nil, fmt.Errorf("%s: NodeSources: Failed to discover edges leaving the Node %s", g.String(), nstr)
	}

	return sources, nil
}
