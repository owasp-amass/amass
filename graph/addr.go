// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"github.com/OWASP/Amass/v3/graph/db"
)

// InsertAddress creates an IP address in the graph and associates it with a source and event.
func (g *Graph) InsertAddress(addr, source, tag, eventID string) (db.Node, error) {
	node, err := g.InsertNodeIfNotExist(addr, "ipaddr")
	if err != nil {
		return node, err
	}

	if err := g.AddNodeToEvent(node, source, tag, eventID); err != nil {
		return node, err
	}

	return node, nil
}

// InsertA creates FQDN, IP address and A record edge in the graph and associates them with a source and event.
func (g *Graph) InsertA(fqdn, addr, source, tag, eventID string) error {
	fqdnNode, err := g.InsertFQDN(fqdn, source, tag, eventID)
	if err != nil {
		return err
	}

	ipNode, err := g.InsertAddress(addr, "DNS", "dns", eventID)
	if err != nil {
		return err
	}

	ipEdge := &db.Edge{
		Predicate: "a_record",
		From:      fqdnNode,
		To:        ipNode,
	}

	if err := g.InsertEdge(ipEdge); err != nil {
		return err
	}

	return nil
}

// InsertAAAA creates FQDN, IP address and AAAA record edge in the graph and associates them with a source and event.
func (g *Graph) InsertAAAA(fqdn, addr, source, tag, eventID string) error {
	fqdnNode, err := g.InsertFQDN(fqdn, source, tag, eventID)
	if err != nil {
		return err
	}

	ipNode, err := g.InsertAddress(addr, "DNS", "dns", eventID)
	if err != nil {
		return err
	}

	ipEdge := &db.Edge{
		Predicate: "aaaa_record",
		From:      fqdnNode,
		To:        ipNode,
	}

	if err := g.InsertEdge(ipEdge); err != nil {
		return err
	}

	return nil
}
