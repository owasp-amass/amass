// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"math/rand"
	"net"
	"strconv"

	"github.com/OWASP/Amass/v3/graph/db"
	"github.com/OWASP/Amass/v3/requests"
	"golang.org/x/net/publicsuffix"
)

// GetOutput returns findings within the enumeration Graph.
func (g *Graph) GetOutput(uuid string) []*requests.Output {
	var results []*requests.Output

	event, err := g.db.ReadNode(uuid)
	if err != nil {
		return results
	}

	edges, err := g.db.ReadOutEdges(event)
	if err != nil {
		return results
	}

	var names []db.Node
	for _, edge := range edges {
		p, err := g.db.ReadProperties(edge.To, "type")

		if err != nil || len(p) == 0 || p[0].Value != "fqdn" {
			continue
		}

		names = append(names, edge.To)
	}

	output := make(chan *requests.Output, 100)
	for _, name := range names {
		go g.buildOutput(name, uuid, output)
	}

	num := len(names)
	for i := 0; i < num; i++ {
		o := <-output

		if o != nil {
			results = append(results, o)
		}
	}

	return results
}

func (g *Graph) buildOutput(sub db.Node, uuid string, c chan *requests.Output) {
	substr := g.db.NodeToID(sub)

	sources, err := g.db.NodeSources(sub, uuid)
	if err != nil {
		c <- nil
		return
	}
	src := sources[randomIndex(len(sources))]

	domain, err := publicsuffix.EffectiveTLDPlusOne(substr)
	if err != nil {
		c <- nil
		return
	}

	output := &requests.Output{
		Name:   substr,
		Domain: domain,
		Tag:    g.SourceTag(src),
		Source: src,
	}

	addrs, err := g.db.NameToIPAddrs(sub)
	if err != nil {
		c <- nil
		return
	}

	var num int
	addrChan := make(chan *requests.AddressInfo, 100)
	for _, addr := range addrs {
		if !g.inEventScope(addr, uuid) {
			continue
		}

		num++
		go g.buildAddrInfo(addr, uuid, addrChan)
	}

	for i := 0; i < num; i++ {
		a := <-addrChan

		if a != nil {
			output.Addresses = append(output.Addresses, *a)
		}
	}

	if len(output.Addresses) == 0 {
		c <- nil
		return
	}

	c <- output
}

func randomIndex(length int) int {
	if length == 1 {
		return 0
	}

	return rand.Intn(length - 1)
}

func (g *Graph) buildAddrInfo(addr db.Node, uuid string, c chan *requests.AddressInfo) {
	if !g.inEventScope(addr, uuid) {
		c <- nil
		return
	}

	ainfo := &requests.AddressInfo{Address: net.ParseIP(g.db.NodeToID(addr))}

	// Get the netblock that contains the IP address
	edges, err := g.db.ReadInEdges(addr, "contains")
	if err != nil {
		c <- nil
		return
	}

	var cidr string
	var cidrNode db.Node
	for _, edge := range edges {
		if g.inEventScope(edge.From, uuid) {
			cidrNode = edge.From
			cidr = g.db.NodeToID(edge.From)
			break
		}
	}
	if cidr == "" {
		c <- nil
		return
	}

	ainfo.CIDRStr = cidr
	_, ainfo.Netblock, _ = net.ParseCIDR(cidr)

	// Get the AS information associated with the netblock
	edges, err = g.db.ReadInEdges(cidrNode, "prefix")
	if err != nil {
		c <- nil
		return
	}

	var asn string
	var asNode db.Node
	for _, edge := range edges {
		if g.inEventScope(edge.From, uuid) {
			asNode = edge.From
			asn = g.db.NodeToID(edge.From)
			break
		}
	}
	if asn == "" {
		c <- nil
		return
	}

	ainfo.ASN, _ = strconv.Atoi(asn)
	if p, err := g.db.ReadProperties(asNode, "description"); err == nil && len(p) > 0 {
		ainfo.Description = p[0].Value
	}

	c <- ainfo
}

// DumpGraph returns all the data being stored in the graph database.
func (g *Graph) DumpGraph() string {
	temp := g.db.(*db.CayleyGraph)

	return temp.DumpGraph()
}
