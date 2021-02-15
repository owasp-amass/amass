// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"fmt"

	"github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/stringset"
	"github.com/cayleygraph/cayley"
	"github.com/cayleygraph/quad"
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

// NameAddrPair represents a relationship between a DNS name and an IP address it eventually resolves to.
type NameAddrPair struct {
	Name string
	Addr string
}

// NamesToAddrs returns a NameAddrPair for each name / address combination discovered in the graph.
func (g *Graph) NamesToAddrs(uuid string, names ...string) ([]*NameAddrPair, error) {
	g.db.Lock()
	defer g.db.Unlock()

	var nameVals []quad.Value
	for _, name := range names {
		nameVals = append(nameVals, quad.IRI(name))
	}

	var filter stringset.Set
	if len(names) > 0 {
		filter = stringset.New(names...)
	}

	nameAddrMap := make(map[string]stringset.Set, len(names))
	f := func(m map[string]quad.Value) {
		name := valToStr(m["name"])
		addr := valToStr(m["address"])

		if filter != nil && !filter.Has(name) {
			return
		}
		if _, found := nameAddrMap[name]; !found {
			nameAddrMap[name] = stringset.New()
		}

		nameAddrMap[name].Insert(addr)
	}

	event := quad.IRI(uuid)
	dns := quad.IRI("DNS")
	ntype := quad.IRI("type")
	cname := quad.IRI("cname_record")
	srvrec := quad.IRI("srv_record")
	arec := quad.IRI("a_record")
	aaaarec := quad.IRI("aaaa_record")
	fqdn := quad.String("fqdn")
	address := quad.String("ipaddr")

	eventNode := cayley.StartPath(g.db.store, event)
	var nodes *cayley.Path
	if len(names) > 0 {
		nodes = cayley.StartPath(g.db.store, nameVals...).Tag("name")
	} else {
		nodes = eventNode.Out().Has(ntype, fqdn).Unique().Tag("name")
	}

	// Obtain the addresses that are associated with the event and adjacent names
	adj := nodes.Out(arec, aaaarec).Has(ntype, address).Tag("address").In(dns).And(eventNode).Back("name")
	if err := adj.Iterate(context.Background()).TagValues(nil, f); err != nil {
		return nil, fmt.Errorf("%s: NamesToAddrs: Failed to iterate over tag values: %v", g.String(), err)
	}

	// Get all the nodes for services names and CNAMES
	p := nodes
	for i := 1; i <= 10; i++ {
		if i == 1 {
			p = p.Out(srvrec, cname)
		} else {
			p = p.Out(cname)
		}
		addrs := p.Out(arec, aaaarec).Has(ntype, address).Tag("address").In(dns).And(eventNode).Back("name")
		if err := addrs.Iterate(context.Background()).TagValues(nil, f); err != nil {
			break
		}
	}

	if len(nameAddrMap) == 0 {
		return nil, fmt.Errorf("%s: NamesToAddrs: No addresses were discovered", g.String())
	}

	pairs := make([]*NameAddrPair, 0, len(nameAddrMap)*2)
	for name, set := range nameAddrMap {
		for addr := range set {
			pairs = append(pairs, &NameAddrPair{
				Name: name,
				Addr: addr,
			})
		}
	}
	return pairs, nil
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
				if err := g.InsertInfrastructure(as.ASN, as.Description, addr, as.Prefix, as.Source, as.Tag, uuid); err != nil {
					continue
				}

				cidr, err = g.db.ReadNode(as.Prefix, "netblock")
				if err != nil {
					continue
				}
			}

			cidrToNode[as.Prefix] = cidr
		}

		if err := g.InsertEdge(&Edge{
			Predicate: "contains",
			From:      cidr,
			To:        node,
		}); err != nil {
			return err
		}
	}

	return nil
}
