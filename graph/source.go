// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"fmt"
	"time"

	"github.com/caffix/stringset"
)

var notDataSourceSet = stringset.New("tld", "root", "domain",
	"cname_record", "ptr_record", "mx_record", "ns_record", "srv_record", "service")

// InsertSource creates a data source node in the graph.
func (g *Graph) InsertSource(source, tag string) (Node, error) {
	node, err := g.InsertNodeIfNotExist(source, "source")
	if err != nil {
		return node, err
	}

	var insert bool
	if p, err := g.db.ReadProperties(node, "tag"); err == nil && len(p) > 0 {
		if p[0].Value != tag {
			// Remove an existing 'tag' property
			if err := g.db.DeleteProperty(node, p[0].Predicate, p[0].Value); err == nil {
				// Update the 'tag' property
				insert = true
			}
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
func (g *Graph) NodeSources(node Node, events ...string) ([]string, error) {
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

// GetSourceData returns the most recent response from the source/tag for the query within the time to live.
func (g *Graph) GetSourceData(source, query string, ttl int) (string, error) {
	node, err := g.db.ReadNode(source, "source")
	if err != nil {
		return "", err
	}

	edges, err := g.db.ReadOutEdges(node, query)
	if err != nil {
		return "", err
	}

	var data string
	for _, edge := range edges {
		p, err := g.db.ReadProperties(edge.To, "timestamp")
		if err != nil || len(p) == 0 {
			continue
		}

		d := time.Duration(ttl) * time.Minute
		ts, err := time.Parse(time.RFC3339, p[0].Value)
		if err != nil || ts.Add(d).Before(time.Now()) {
			continue
		}

		p, err = g.db.ReadProperties(edge.To, "response")
		if err != nil || len(p) == 0 {
			continue
		}

		data = p[0].Value
		break
	}

	if data == "" {
		return "", fmt.Errorf("%s: GetSourceData: Failed to obtain a cached response from %s for query %s", g.String(), source, query)
	}

	return data, nil
}

// CacheSourceData inserts an updated response from the source/tag for the query.
func (g *Graph) CacheSourceData(source, tag, query, resp string) error {
	snode, err := g.InsertSource(source, tag)
	if err != nil {
		return err
	}

	// Remove previously cached responses for the same query
	if err := g.deleteCachedData(source, query); err != nil {
		return err
	}

	ts := time.Now().Format(time.RFC3339)
	rnode, err := g.InsertNodeIfNotExist(source+"-response-"+ts, "response")
	if err != nil {
		return err
	}

	if err := g.db.InsertProperty(rnode, "timestamp", ts); err != nil {
		return err
	}

	if err := g.db.InsertProperty(rnode, "response", resp); err != nil {
		return err
	}

	return g.InsertEdge(&Edge{
		Predicate: query,
		From:      snode,
		To:        rnode,
	})
}

func (g *Graph) deleteCachedData(source, query string) error {
	node, err := g.db.ReadNode(source, "source")
	if err != nil {
		return err
	}

	edges, err := g.db.ReadOutEdges(node, query)
	if err != nil {
		return err
	}

	for _, edge := range edges {
		if err := g.db.DeleteNode(edge.To); err != nil {
			return err
		}
		if err := g.db.DeleteEdge(edge); err != nil {
			return err
		}
	}

	return nil
}
