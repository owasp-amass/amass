// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"net"
	"strconv"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
)

// InsertAS adds/updates an autonomous system in the graph.
func (g *Graph) InsertAS(asn, desc, source, tag, eventID string) (Node, error) {
	asNode, err := g.InsertNodeIfNotExist(asn, "as")
	if err != nil {
		return asNode, err
	}

	var insert bool
	p, err := g.db.ReadProperties(asNode, "description")
	if err == nil && len(p) > 0 {
		if p[0].Value != desc {
			// Update the 'desc' property
			if err := g.db.DeleteProperty(asNode, p[0].Predicate, p[0].Value); err == nil {
				insert = true
			}
		}
	} else {
		// The description was not found
		insert = true
	}

	if insert {
		if err := g.db.InsertProperty(asNode, "description", desc); err != nil {
			return asNode, err
		}
	}

	if err := g.AddNodeToEvent(asNode, source, tag, eventID); err != nil {
		return asNode, err
	}

	return asNode, nil
}

// InsertInfrastructure adds/updates an associated IP address, netblock and autonomous system in the graph.
func (g *Graph) InsertInfrastructure(asn int, desc, addr, cidr, source, tag, eventID string) error {
	ipNode, err := g.InsertAddress(addr, "DNS", "dns", eventID)
	if err != nil {
		return err
	}

	cidrNode, err := g.InsertNetblock(cidr, source, tag, eventID)
	if err != nil {
		return err
	}

	// Create the edge between the CIDR and the address
	containsEdge := &Edge{
		Predicate: "contains",
		From:      cidrNode,
		To:        ipNode,
	}
	if err := g.InsertEdge(containsEdge); err != nil {
		return err
	}

	asNode, err := g.InsertAS(strconv.Itoa(asn), desc, source, tag, eventID)
	if err != nil {
		return err
	}

	// Create the edge between the AS and the netblock
	prefixEdge := &Edge{
		Predicate: "prefix",
		From:      asNode,
		To:        cidrNode,
	}

	return g.InsertEdge(prefixEdge)
}

// ReadASDescription the description property of an autonomous system in the graph.
func (g *Graph) ReadASDescription(asn string) string {
	if asNode, err := g.db.ReadNode(asn, "as"); err == nil {
		return g.nodeDescription(asNode)
	}

	return ""
}

func (g *Graph) nodeDescription(node Node) string {
	if p, err := g.db.ReadProperties(node, "description"); err == nil && len(p) > 0 {
		return p[0].Value
	}

	return ""
}

// ASNCacheFill populates an ASNCache object with the AS data in the receiver object.
func (g *Graph) ASNCacheFill(cache *amassnet.ASNCache) error {
	nodes, err := g.AllNodesOfType("as")
	if err != nil {
		return err
	}

	for _, as := range nodes {
		id := g.db.NodeToID(as)
		asn, _ := strconv.Atoi(id)
		if asn <= 0 {
			continue
		}

		desc := g.nodeDescription(as)
		if g.alreadyClosed {
			return nil
		}

		edges, err := g.db.ReadOutEdges(as, "prefix")
		if err != nil {
			continue
		}

		for _, edge := range edges {
			if g.alreadyClosed {
				return nil
			}

			if _, cidr, err := net.ParseCIDR(g.db.NodeToID(edge.To)); err == nil {
				cache.Update(&requests.ASNRequest{
					Address:     cidr.IP.String(),
					ASN:         asn,
					Prefix:      cidr.String(),
					Description: desc,
					Tag:         requests.RIR,
					Source:      g.String(),
				})
			}
		}
	}
	return nil
}
