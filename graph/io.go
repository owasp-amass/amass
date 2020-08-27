// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package graph

import (
	"context"
	"math/rand"
	"net"
	"strconv"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringfilter"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/sync/semaphore"
)

// EventOutput returns findings within the receiver Graph for the event identified by the uuid string
// parameter and not already in the filter StringFilter argument. The cache ASNCache argument provides
// ASN / netblock information already discovered so the routine can avoid unnecessary queries to the
// graph database. The filter and cache objects are updated by EventOutput.
func (g *Graph) EventOutput(uuid string, filter stringfilter.Filter, asninfo bool, cache *amassnet.ASNCache) []*requests.Output {
	var results []*requests.Output

	names := g.getEventNameNodes(uuid)
	if len(names) == 0 {
		return results
	}

	// Make sure a filter has been created
	if filter == nil {
		filter = stringfilter.NewStringFilter()
	}

	// Make sure a cache has been created for performance purposes
	if asninfo && cache == nil {
		cache = amassnet.NewASNCache()
	}

	var count int
	sem := semaphore.NewWeighted(10)
	output := make(chan *requests.Output, len(names))
	for _, name := range names {
		if n := g.db.NodeToID(name); n == "" || filter.Has(n) {
			continue
		}

		sem.Acquire(context.TODO(), 1)
		go g.buildOutput(name, uuid, asninfo, cache, output, sem)
		count++
	}

	for i := 0; i < count; i++ {
		if o := <-output; o != nil && !filter.Duplicate(o.Name) {
			results = append(results, o)
		}
	}

	return results
}

// EventNames returns findings within the receiver Graph for the event identified by the uuid string
// parameter and not already in the filter StringFilter argument. The filter is updated by EventNames.
func (g *Graph) EventNames(uuid string, filter stringfilter.Filter) []*requests.Output {
	var results []*requests.Output

	names := g.getEventNameNodes(uuid)
	if len(names) == 0 {
		return results
	}

	// Make sure a filter has been created
	if filter == nil {
		filter = stringfilter.NewStringFilter()
	}

	for _, name := range names {
		if o := g.buildNameInfo(name, uuid); o != nil && !filter.Duplicate(o.Name) {
			results = append(results, o)
		}
	}

	return results
}

func (g *Graph) getEventNameNodes(uuid string) []Node {
	var names []Node

	event, err := g.db.ReadNode(uuid, "event")
	if err != nil {
		return names
	}

	edges, err := g.db.ReadOutEdges(event)
	if err != nil {
		return names
	}

	for _, edge := range edges {
		p, err := g.db.ReadProperties(edge.To, "type")

		if err != nil || len(p) == 0 || p[0].Value != "fqdn" {
			continue
		}

		names = append(names, edge.To)
	}

	return names
}

func (g *Graph) buildOutput(sub Node, uuid string, asninfo bool,
	cache *amassnet.ASNCache, c chan *requests.Output, sem *semaphore.Weighted) {
	defer sem.Release(1)

	output := g.buildNameInfo(sub, uuid)
	if output == nil {
		c <- nil
		return
	}

	addrs, err := g.NameToAddrs(sub)
	if err != nil {
		c <- nil
		return
	}

	var num int
	addrChan := make(chan *requests.AddressInfo, 100)
	for _, addr := range addrs {
		if !g.InEventScope(addr, uuid, "DNS") {
			continue
		}

		num++
		go g.buildAddrInfo(addr, uuid, asninfo, cache, addrChan)
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

func (g *Graph) buildNameInfo(sub Node, uuid string) *requests.Output {
	substr := g.db.NodeToID(sub)

	sources, err := g.NodeSources(sub, uuid)
	if err != nil {
		return nil
	}
	src := sources[0]

	domain, err := publicsuffix.EffectiveTLDPlusOne(substr)
	if err != nil {
		return nil
	}

	return &requests.Output{
		Name:   substr,
		Domain: domain,
		Tag:    g.SourceTag(src),
		Source: src,
	}
}

func (g *Graph) buildAddrInfo(addr Node, uuid string, asninfo bool, cache *amassnet.ASNCache, c chan *requests.AddressInfo) {
	if !g.InEventScope(addr, uuid, "DNS") {
		c <- nil
		return
	}

	address := g.db.NodeToID(addr)
	ainfo := &requests.AddressInfo{Address: net.ParseIP(address)}
	// Check if this request is just for the address
	if !asninfo {
		c <- ainfo
		return
	}

	// Check the ASNCache before querying the graph database
	if a := cache.AddrSearch(address); a != nil {
		var err error

		_, ainfo.Netblock, err = net.ParseCIDR(a.Prefix)
		if err == nil && ainfo.Netblock.Contains(ainfo.Address) {
			ainfo.ASN = a.ASN
			ainfo.Description = a.Description
			ainfo.CIDRStr = a.Prefix
			c <- ainfo
			return
		}
	}

	// Get the netblock that contains the IP address
	edges, err := g.db.ReadInEdges(addr, "contains")
	if err != nil {
		c <- nil
		return
	}

	var cidr string
	var cidrNode Node
	for _, edge := range edges {
		if g.InEventScope(edge.From, uuid, "RIR") {
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
	var asNode Node
	for _, edge := range edges {
		if g.InEventScope(edge.From, uuid, "RIR") {
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
	ainfo.Description = g.nodeDescription(asNode)

	cache.Update(&requests.ASNRequest{
		Address:     ainfo.Address.String(),
		ASN:         ainfo.ASN,
		Prefix:      ainfo.CIDRStr,
		Description: ainfo.Description,
	})

	c <- ainfo
}
