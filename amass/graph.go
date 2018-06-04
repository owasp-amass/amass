// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strconv"
	"sync"
)

type Edge struct {
	From, To *Node
	Label    string
}

type Node struct {
	Edges      []*Edge
	Labels     []string
	Properties map[string]string
}

type Graph struct {
	sync.Mutex
	Domains    map[string]*Node
	Subdomains map[string]*Node
	Addresses  map[string]*Node
	PTRs       map[string]*Node
	Netblocks  map[string]*Node
	ASNs       map[int]*Node
}

func NewGraph() *Graph {
	return &Graph{
		Domains:    make(map[string]*Node),
		Subdomains: make(map[string]*Node),
		Addresses:  make(map[string]*Node),
		PTRs:       make(map[string]*Node),
		Netblocks:  make(map[string]*Node),
		ASNs:       make(map[int]*Node),
	}
}

func NewNode(label string) *Node {
	n := &Node{Properties: make(map[string]string)}

	n.Labels = append(n.Labels, label)
	return n
}

func NewEdge(from, to *Node, label string) *Edge {
	// Do not insert duplicate edges
	for _, edge := range from.Edges {
		if edge.Label == label && edge.From == from && edge.To == to {
			return nil
		}
	}

	e := &Edge{
		From:  from,
		To:    to,
		Label: label,
	}

	from.Edges = append(from.Edges, e)
	to.Edges = append(to.Edges, e)
	return e
}

func (g *Graph) insertDomain(domain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if _, found := g.Domains[domain]; found {
		return
	}

	d := NewNode("Domain")
	d.Labels = append(d.Labels, "Subdomain")
	d.Properties["name"] = domain
	d.Properties["tag"] = tag
	d.Properties["source"] = source
	g.Domains[domain] = d
	g.Subdomains[domain] = d
}

func (g *Graph) insertCNAME(name, domain, target, tdomain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub

		}

		d := g.Domains[domain]
		s := g.Subdomains[name]
		NewEdge(d, s, "ROOT_OF")
	}

	if target != tdomain {
		if _, found := g.Subdomains[target]; !found {
			sub := NewNode("Subdomain")
			sub.Properties["name"] = target
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[target] = sub
		}

		d := g.Domains[tdomain]
		s := g.Subdomains[target]
		NewEdge(d, s, "ROOT_OF")
	}

	s1 := g.Subdomains[name]
	s2 := g.Subdomains[target]
	NewEdge(s1, s2, "CNAME_TO")
}

func (g *Graph) insertA(name, domain, addr, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub

		}

		d := g.Domains[domain]
		s := g.Subdomains[name]
		NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.Addresses[addr]; !found {
		a := NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv4"
		g.Addresses[addr] = a
	}

	s := g.Subdomains[name]
	a := g.Addresses[addr]
	NewEdge(s, a, "A_TO")
}

func (g *Graph) insertAAAA(name, domain, addr, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub

		}

		d := g.Domains[domain]
		s := g.Subdomains[name]
		NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.Addresses[addr]; !found {
		a := NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv6"
		g.Addresses[addr] = a
	}

	s := g.Subdomains[name]
	a := g.Addresses[addr]
	NewEdge(s, a, "AAAA_TO")
}

func (g *Graph) insertPTR(name, domain, target, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if target != domain {
		if _, found := g.Subdomains[target]; !found {
			sub := NewNode("Subdomain")
			sub.Properties["name"] = target
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[target] = sub
		}

		d := g.Domains[domain]
		s := g.Subdomains[target]
		NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.PTRs[name]; !found {
		ptr := NewNode("PTR")
		ptr.Properties["name"] = name
		g.PTRs[name] = ptr
	}

	p := g.PTRs[name]
	s := g.Subdomains[target]
	NewEdge(p, s, "PTR_TO")
}

func (g *Graph) insertSRV(name, domain, service, target, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub
		}
	}

	if _, found := g.Subdomains[service]; !found {
		sub := NewNode("Subdomain")
		sub.Properties["name"] = service
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[service] = sub
	}

	if _, found := g.Subdomains[target]; !found {
		sub := NewNode("Subdomain")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[target] = sub
	}

	d := g.Domains[domain]
	srv := g.Subdomains[service]
	NewEdge(d, srv, "ROOT_OF")

	sub := g.Subdomains[name]
	NewEdge(srv, sub, "SERVICE_FOR")

	t := g.Subdomains[target]
	NewEdge(srv, t, "SRV_TO")
}

func (g *Graph) insertNS(name, domain, target, tdomain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if _, found := g.Subdomains[name]; !found {
		sub := NewNode("Subdomain")
		sub.Properties["name"] = name
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[name] = sub
	}

	if _, found := g.Subdomains[target]; !found {
		sub := NewNode("Subdomain")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[target] = sub
	}

	if target != tdomain {
		d := g.Domains[tdomain]
		s := g.Subdomains[target]
		NewEdge(d, s, "ROOT_OF")
	}

	sub := g.Subdomains[name]
	ns := g.Subdomains[target]
	ns.Properties["type"] = "TypeNS"
	ns.Labels = append(ns.Labels, "NS")
	NewEdge(sub, ns, "NS_TO")
}

func (g *Graph) insertMX(name, domain, target, tdomain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if _, found := g.Subdomains[name]; !found {
		sub := NewNode("Subdomain")
		sub.Properties["name"] = name
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[name] = sub
	}

	if _, found := g.Subdomains[target]; !found {
		sub := NewNode("Subdomain")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[target] = sub
	}

	if target != tdomain {
		d := g.Domains[tdomain]
		mx := g.Subdomains[target]
		NewEdge(d, mx, "ROOT_OF")
	}

	sub := g.Subdomains[name]
	mx := g.Subdomains[target]
	mx.Properties["type"] = "TypeMX"
	mx.Labels = append(mx.Labels, "MX")
	NewEdge(sub, mx, "MX_TO")
}

func (g *Graph) insertInfrastructure(addr string, asn int, cidr *net.IPNet, desc string) {
	g.Lock()
	defer g.Unlock()

	nb := cidr.String()
	if _, found := g.Netblocks[nb]; !found {
		n := NewNode("Netblock")
		n.Properties["cidr"] = nb
		g.Netblocks[nb] = n
	}

	a := g.Addresses[addr]
	n := g.Netblocks[nb]
	NewEdge(n, a, "CONTAINS")

	if _, found := g.ASNs[asn]; !found {
		as := NewNode("AS")
		as.Properties["asn"] = strconv.Itoa(asn)
		as.Properties["desc"] = desc
		g.ASNs[asn] = as
	}

	as := g.ASNs[asn]
	NewEdge(as, n, "HAS_PREFIX")
}
