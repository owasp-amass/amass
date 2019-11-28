// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"github.com/OWASP/Amass/v3/graph/db"
)

// InsertSource creates a data source node in the graph.
func (g *Graph) InsertSource(source, tag string) (db.Node, error) {
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

	node, err := g.db.ReadNode(source)
	if err != nil {
		return ""
	}

	if p, err := g.db.ReadProperties(node, "tag"); err == nil && len(p) > 0 {
		return p[0].Value
	}

	return ""
}
