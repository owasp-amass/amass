// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"fmt"

	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
)

// InsertAddress creates an IP address in the graph and associates it with a source and event.
func (g *Graph) InsertAddress(addr, source, tag, eventID string) (Node, error) {
	node, err := g.InsertNodeIfNotExist(addr, "ipaddr")
	if err != nil {
		return node, err
	}

	if err := g.AddNodeToEvent(node, source, tag, eventID); err != nil {
		return node, err
	}

	return node, nil
}

// NameToAddrs obtains each ipaddr Node that the parameter Node has resolved to.
func (g *Graph) NameToAddrs(node Node) ([]Node, error) {
	nstr := g.db.NodeToID(node)
	if nstr == "" {
		return nil, fmt.Errorf("%s: NameToIPAddrs: Invalid node reference argument", g.String())
	}

	// Attempt to obtain the SRV record out-edge for the Node parameter
	edges, err := g.db.ReadOutEdges(node, "srv_record")
	if err == nil && len(edges) > 0 {
		// A SRV record was discovered for the Node parameter
		for _, edge := range edges {
			if edge.Predicate == "srv_record" {
				// Set the node to the one pointed to by the SRV record
				node = edge.To
				break
			}
		}
	}

	// Traverse CNAME and A/AAAA records
	nodes, err := g.CNAMEToAddrs(node)

	if len(nodes) > 0 {
		return nodes, err
	}

	return nodes, fmt.Errorf("%s: NameToIPAddrs: No addresses were discovered for %s", g.String(), nstr)
}

// CNAMEToAddrs traverses CNAME records, starting with the parameter Node, and obtains the network addresses they eventually resolve to.
func (g *Graph) CNAMEToAddrs(node Node) ([]Node, error) {
	cur := node
	var nodes []Node
	filter := stringfilter.NewStringFilter()

	// Do not recursively follow the CNAMEs for more than 10 records
traversal:
	for i := 0; i < 10; i++ {
		// Get all the out-edges of interest for the current Node parameter
		edges, err := g.db.ReadOutEdges(cur, "cname_record", "a_record", "aaaa_record")
		if err != nil {
			return nil, fmt.Errorf("%s: CNAMEToAddrs: No records found for Node %s: %v", g.String(), g.db.NodeToID(cur), err)
		}

		for _, edge := range edges {
			if edge.Predicate == "cname_record" {
				if filter.Has(g.db.NodeToID(edge.To)) {
					break traversal
				}

				cur = edge.To
				continue traversal
			}
		}

		for _, edge := range edges {
			nodes = append(nodes, edge.To)
		}
		break
	}

	return nodes, nil
}

// InsertA creates FQDN, IP address and A record edge in the graph and associates them with a source and event.
func (g *Graph) InsertA(fqdn, addr, source, tag, eventID string) error {
	fqdnNode, err := g.InsertFQDN(fqdn, source, tag, eventID)
	if err != nil {
		return err
	}

	ipNode, err := g.InsertAddress(addr, "DNS", requests.DNS, eventID)
	if err != nil {
		return err
	}

	ipEdge := &Edge{
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

	ipNode, err := g.InsertAddress(addr, "DNS", requests.DNS, eventID)
	if err != nil {
		return err
	}

	ipEdge := &Edge{
		Predicate: "aaaa_record",
		From:      fqdnNode,
		To:        ipNode,
	}

	if err := g.InsertEdge(ipEdge); err != nil {
		return err
	}

	return nil
}

// HealAddressNodes looks for 'ipaddr' nodes in the graph and creates missing edges to the
// appropriate 'netblock' nodes using data provided by the ASNCache parameter.
func (g *Graph) HealAddressNodes(cache *net.ASNCache, uuid string) error {
	var err error
	cidrToNode := make(map[string]Node)

	if cache == nil {
		cache = net.NewASNCache()

		if err = g.ASNCacheFill(cache); err != nil {
			return err
		}
	}

	nodes, err := g.AllNodesOfType("ipaddr", uuid)
	if err != nil {
		return err
	}

	for _, node := range nodes {
		addr := g.db.NodeToID(node)

		as := cache.AddrSearch(addr)
		if as == nil {
			continue
		}

		cidr, found := cidrToNode[as.Prefix]
		if !found {
			cidr, err = g.db.ReadNode(as.Prefix, "netblock")
			if err != nil {
				g.InsertInfrastructure(as.ASN, as.Description, addr, as.Prefix, as.Source, as.Tag, uuid)

				cidr, err = g.db.ReadNode(as.Prefix, "netblock")
				if err != nil {
					continue
				}
			}

			cidrToNode[as.Prefix] = cidr
		}

		g.InsertEdge(&Edge{
			Predicate: "contains",
			From:      cidr,
			To:        node,
		})
	}

	return nil
}
