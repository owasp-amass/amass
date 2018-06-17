// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strconv"
	"sync"

	"github.com/caffix/amass/amass/internal/viz"
)

type Edge struct {
	From, To int
	Label    string
	idx      int
}

type Node struct {
	Edges      []int
	Labels     []string
	Properties map[string]string
	idx        int
}

type Graph struct {
	sync.Mutex
	Domains    map[string]*Node
	Subdomains map[string]*Node
	Addresses  map[string]*Node
	PTRs       map[string]*Node
	Netblocks  map[string]*Node
	ASNs       map[int]*Node
	nodes      []*Node
	curNodeIdx int
	edges      []*Edge
	curEdgeIdx int
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

func (g *Graph) NewNode(label string) *Node {
	n := &Node{
		Properties: make(map[string]string),
		idx:        g.curNodeIdx,
	}

	g.curNodeIdx++

	g.nodes = append(g.nodes, n)
	n.Labels = append(n.Labels, label)
	return n
}

func (g *Graph) NewEdge(from, to int, label string) *Edge {
	// Do not insert duplicate edges
	n := g.nodes[from]
	for _, idx := range n.Edges {
		edge := g.edges[idx]
		if edge.Label == label && edge.From == from && edge.To == to {
			return nil
		}
	}

	e := &Edge{
		From:  from,
		To:    to,
		Label: label,
		idx:   g.curEdgeIdx,
	}

	g.curEdgeIdx++

	g.nodes[from].Edges = append(g.nodes[from].Edges, e.idx)
	g.nodes[to].Edges = append(g.nodes[to].Edges, e.idx)
	g.edges = append(g.edges, e)
	return e
}

func (g *Graph) VizData() ([]viz.Node, []viz.Edge) {
	g.Lock()
	defer g.Unlock()

	var nodes []viz.Node
	var edges []viz.Edge

	for _, edge := range g.edges {
		edges = append(edges, viz.Edge{
			From:  edge.From,
			To:    edge.To,
			Title: edge.Label,
		})
	}

	for idx, node := range g.nodes {
		var label, title, source string
		t := node.Labels[0]

		switch t {
		case "Subdomain":
			label = node.Properties["name"]
			title = t + ": " + label
			source = node.Properties["source"]
		case "Domain":
			label = node.Properties["name"]
			title = t + ": " + label
			source = node.Properties["source"]
		case "IPAddress":
			label = node.Properties["addr"]
			title = t + ": " + label
		case "PTR":
			label = node.Properties["name"]
			title = t + ": " + label
		case "NS":
			label = node.Properties["name"]
			title = t + ": " + label
			source = node.Properties["source"]
		case "MX":
			label = node.Properties["name"]
			title = t + ": " + label
			source = node.Properties["source"]
		case "Netblock":
			label = node.Properties["cidr"]
			title = t + ": " + label
		case "AS":
			label = node.Properties["asn"]
			title = t + ": " + label + ", Desc: " + node.Properties["desc"]
		}

		nodes = append(nodes, viz.Node{
			ID:     idx,
			Type:   t,
			Label:  label,
			Title:  title,
			Source: source,
		})
	}
	return nodes, edges
}

func (g *Graph) insertDomain(domain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if _, found := g.Domains[domain]; found {
		return
	}

	if d, found := g.Subdomains[domain]; !found {
		d := g.NewNode("Domain")
		d.Labels = append(d.Labels, "Subdomain")
		d.Properties["name"] = domain
		d.Properties["tag"] = tag
		d.Properties["source"] = source
		g.Domains[domain] = d
		g.Subdomains[domain] = d
	} else {
		d.Labels = []string{"Domain", "Subdomain"}
		g.Domains[domain] = d
	}

}

func (g *Graph) insertCNAME(name, domain, target, tdomain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := g.NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub

		}

		d := g.Domains[domain].idx
		s := g.Subdomains[name].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if target != tdomain {
		if _, found := g.Subdomains[target]; !found {
			sub := g.NewNode("Subdomain")
			sub.Properties["name"] = target
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[target] = sub
		}

		d := g.Domains[tdomain].idx
		s := g.Subdomains[target].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	s1 := g.Subdomains[name].idx
	s2 := g.Subdomains[target].idx
	g.NewEdge(s1, s2, "CNAME_TO")
}

func (g *Graph) insertA(name, domain, addr, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := g.NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub

		}

		d := g.Domains[domain].idx
		s := g.Subdomains[name].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.Addresses[addr]; !found {
		a := g.NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv4"
		g.Addresses[addr] = a
	}

	s := g.Subdomains[name].idx
	a := g.Addresses[addr].idx
	g.NewEdge(s, a, "A_TO")
}

func (g *Graph) insertAAAA(name, domain, addr, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := g.NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub

		}

		d := g.Domains[domain].idx
		s := g.Subdomains[name].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.Addresses[addr]; !found {
		a := g.NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv6"
		g.Addresses[addr] = a
	}

	s := g.Subdomains[name].idx
	a := g.Addresses[addr].idx
	g.NewEdge(s, a, "AAAA_TO")
}

func (g *Graph) insertPTR(name, domain, target, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if target != domain {
		if _, found := g.Subdomains[target]; !found {
			sub := g.NewNode("Subdomain")
			sub.Properties["name"] = target
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[target] = sub
		}

		d := g.Domains[domain].idx
		s := g.Subdomains[target].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.PTRs[name]; !found {
		ptr := g.NewNode("PTR")
		ptr.Properties["name"] = name
		g.PTRs[name] = ptr
	}

	p := g.PTRs[name].idx
	s := g.Subdomains[target].idx
	g.NewEdge(p, s, "PTR_TO")
}

func (g *Graph) insertSRV(name, domain, service, target, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			sub := g.NewNode("Subdomain")
			sub.Properties["name"] = name
			sub.Properties["tag"] = tag
			sub.Properties["source"] = source
			g.Subdomains[name] = sub
		}
	}

	if _, found := g.Subdomains[service]; !found {
		sub := g.NewNode("Subdomain")
		sub.Properties["name"] = service
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[service] = sub
	}

	if _, found := g.Subdomains[target]; !found {
		sub := g.NewNode("Subdomain")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[target] = sub
	}

	d := g.Domains[domain].idx
	srv := g.Subdomains[service].idx
	g.NewEdge(d, srv, "ROOT_OF")

	sub := g.Subdomains[name].idx
	g.NewEdge(srv, sub, "SERVICE_FOR")

	t := g.Subdomains[target].idx
	g.NewEdge(srv, t, "SRV_TO")
}

func (g *Graph) insertNS(name, domain, target, tdomain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if _, found := g.Subdomains[name]; !found {
		sub := g.NewNode("Subdomain")
		sub.Properties["name"] = name
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[name] = sub
	}

	if ns, found := g.Subdomains[target]; !found {
		sub := g.NewNode("NS")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		sub.Labels = append(sub.Labels, "Subdomain")
		g.Subdomains[target] = sub
	} else {
		ns.Labels = []string{"NS", "Subdomain"}
	}

	if target != tdomain {
		d := g.Domains[tdomain].idx
		s := g.Subdomains[target].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	sub := g.Subdomains[name].idx
	ns := g.Subdomains[target].idx
	g.NewEdge(sub, ns, "NS_TO")
}

func (g *Graph) insertMX(name, domain, target, tdomain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if _, found := g.Subdomains[name]; !found {
		sub := g.NewNode("Subdomain")
		sub.Properties["name"] = name
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		g.Subdomains[name] = sub
	}

	if mx, found := g.Subdomains[target]; !found {
		sub := g.NewNode("MX")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		sub.Labels = append(sub.Labels, "Subdomain")
		g.Subdomains[target] = sub
	} else {
		mx.Labels = []string{"MX", "Subdomain"}
	}

	if target != tdomain {
		d := g.Domains[tdomain].idx
		mx := g.Subdomains[target].idx
		g.NewEdge(d, mx, "ROOT_OF")
	}

	sub := g.Subdomains[name].idx
	mx := g.Subdomains[target].idx
	g.NewEdge(sub, mx, "MX_TO")
}

func (g *Graph) insertInfrastructure(addr string, asn int, cidr *net.IPNet, desc string) {
	g.Lock()
	defer g.Unlock()

	nb := cidr.String()
	if _, found := g.Netblocks[nb]; !found {
		n := g.NewNode("Netblock")
		n.Properties["cidr"] = nb
		g.Netblocks[nb] = n
	}

	a := g.Addresses[addr].idx
	n := g.Netblocks[nb].idx
	g.NewEdge(n, a, "CONTAINS")

	if _, found := g.ASNs[asn]; !found {
		as := g.NewNode("AS")
		as.Properties["asn"] = strconv.Itoa(asn)
		as.Properties["desc"] = desc
		g.ASNs[asn] = as
	}

	as := g.ASNs[asn].idx
	g.NewEdge(as, n, "HAS_PREFIX")
}
