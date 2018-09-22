// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils/viz"
)

var (
	WebRegex *regexp.Regexp = regexp.MustCompile("web|www")
)

type Edge struct {
	From, To int
	Label    string
	idx      int
}

type Node struct {
	sync.Mutex
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
	Nodes      []*Node
	curNodeIdx int
	Edges      []*Edge
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
	g.Lock()
	defer g.Unlock()

	n := &Node{
		Properties: make(map[string]string),
		idx:        g.curNodeIdx,
	}

	g.curNodeIdx++

	g.Nodes = append(g.Nodes, n)
	n.Labels = append(n.Labels, label)
	return n
}

func (g *Graph) NewEdge(from, to int, label string) *Edge {
	g.Lock()
	defer g.Unlock()

	// Do not insert duplicate edges
	n := g.Nodes[from]
	n.Lock()
	defer n.Unlock()
	for _, idx := range n.Edges {
		edge := g.Edges[idx]
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
	g.Nodes[from].Edges = append(g.Nodes[from].Edges, e.idx)
	g.Nodes[to].Lock()
	g.Nodes[to].Edges = append(g.Nodes[to].Edges, e.idx)
	g.Nodes[to].Unlock()
	g.Edges = append(g.Edges, e)
	return e
}

func (g *Graph) VizData() ([]viz.Node, []viz.Edge) {
	g.Lock()
	defer g.Unlock()

	var nodes []viz.Node
	var edges []viz.Edge

	for _, edge := range g.Edges {
		edges = append(edges, viz.Edge{
			From:  edge.From,
			To:    edge.To,
			Title: edge.Label,
		})
	}

	for idx, node := range g.Nodes {
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

func (g *Graph) InsertSubdomain(name, tag, source string) {
	sub := g.NewNode("Subdomain")

	sub.Properties["name"] = name
	sub.Properties["tag"] = tag
	sub.Properties["source"] = source
	g.Lock()
	g.Subdomains[name] = sub
	g.Unlock()
}

func (g *Graph) InsertDomain(domain, tag, source string) error {
	if _, found := g.Domains[domain]; found {
		return nil
	}

	if d, found := g.Subdomains[domain]; !found {
		d := g.NewNode("Domain")
		d.Labels = append(d.Labels, "Subdomain")
		d.Properties["name"] = domain
		d.Properties["tag"] = tag
		d.Properties["source"] = source
		g.Lock()
		g.Domains[domain] = d
		g.Subdomains[domain] = d
		g.Unlock()
	} else {
		d.Labels = []string{"Domain", "Subdomain"}
		g.Lock()
		g.Domains[domain] = d
		g.Unlock()
	}
	return nil
}

func (g *Graph) InsertCNAME(name, domain, target, tdomain, tag, source string) error {
	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			g.InsertSubdomain(name, tag, source)
		}
		d := g.Domains[domain].idx
		s := g.Subdomains[name].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if target != tdomain {
		if _, found := g.Subdomains[target]; !found {
			g.InsertSubdomain(target, tag, source)
		}
		d := g.Domains[tdomain].idx
		s := g.Subdomains[target].idx
		g.NewEdge(d, s, "ROOT_OF")
	}
	s1 := g.Subdomains[name].idx
	s2 := g.Subdomains[target].idx
	g.NewEdge(s1, s2, "CNAME_TO")
	return nil
}

func (g *Graph) InsertA(name, domain, addr, tag, source string) error {
	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			g.InsertSubdomain(name, tag, source)
		}
		d := g.Domains[domain].idx
		s := g.Subdomains[name].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.Addresses[addr]; !found {
		a := g.NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv4"
		g.Lock()
		g.Addresses[addr] = a
		g.Unlock()
	}
	s := g.Subdomains[name].idx
	a := g.Addresses[addr].idx
	g.NewEdge(s, a, "A_TO")
	return nil
}

func (g *Graph) InsertAAAA(name, domain, addr, tag, source string) error {
	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			g.InsertSubdomain(name, tag, source)
		}
		d := g.Domains[domain].idx
		s := g.Subdomains[name].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.Addresses[addr]; !found {
		a := g.NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv6"
		g.Lock()
		g.Addresses[addr] = a
		g.Unlock()
	}
	s := g.Subdomains[name].idx
	a := g.Addresses[addr].idx
	g.NewEdge(s, a, "AAAA_TO")
	return nil
}

func (g *Graph) InsertPTR(name, domain, target, tag, source string) error {
	if target != domain {
		if _, found := g.Subdomains[target]; !found {
			g.InsertSubdomain(target, tag, source)
		}
		d := g.Domains[domain].idx
		s := g.Subdomains[target].idx
		g.NewEdge(d, s, "ROOT_OF")
	}

	if _, found := g.PTRs[name]; !found {
		ptr := g.NewNode("PTR")
		ptr.Properties["name"] = name
		g.Lock()
		g.PTRs[name] = ptr
		g.Unlock()
	}
	p := g.PTRs[name].idx
	s := g.Subdomains[target].idx
	g.NewEdge(p, s, "PTR_TO")
	return nil
}

func (g *Graph) InsertSRV(name, domain, service, target, tag, source string) error {
	if name != domain {
		if _, found := g.Subdomains[name]; !found {
			g.InsertSubdomain(name, tag, source)
		}
	}

	if _, found := g.Subdomains[service]; !found {
		g.InsertSubdomain(service, tag, source)
	}

	if _, found := g.Subdomains[target]; !found {
		g.InsertSubdomain(target, tag, source)
	}

	d := g.Domains[domain].idx
	srv := g.Subdomains[service].idx
	g.NewEdge(d, srv, "ROOT_OF")

	sub := g.Subdomains[name].idx
	g.NewEdge(srv, sub, "SERVICE_FOR")

	t := g.Subdomains[target].idx
	g.NewEdge(srv, t, "SRV_TO")
	return nil
}

func (g *Graph) InsertNS(name, domain, target, tdomain, tag, source string) error {
	if _, found := g.Subdomains[name]; !found {
		g.InsertSubdomain(name, tag, source)
	}

	if ns, found := g.Subdomains[target]; !found {
		sub := g.NewNode("NS")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		sub.Labels = append(sub.Labels, "Subdomain")
		g.Lock()
		g.Subdomains[target] = sub
		g.Unlock()
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
	return nil
}

func (g *Graph) InsertMX(name, domain, target, tdomain, tag, source string) error {
	if _, found := g.Subdomains[name]; !found {
		g.InsertSubdomain(name, tag, source)
	}

	if mx, found := g.Subdomains[target]; !found {
		sub := g.NewNode("MX")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		sub.Labels = append(sub.Labels, "Subdomain")
		g.Lock()
		g.Subdomains[target] = sub
		g.Unlock()
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
	return nil
}

func (g *Graph) InsertInfrastructure(addr string, asn int, cidr *net.IPNet, desc string) error {
	nb := cidr.String()
	if _, found := g.Netblocks[nb]; !found {
		n := g.NewNode("Netblock")
		n.Properties["cidr"] = nb
		g.Lock()
		g.Netblocks[nb] = n
		g.Unlock()
	}
	a := g.Addresses[addr].idx
	n := g.Netblocks[nb].idx
	g.NewEdge(n, a, "CONTAINS")

	if _, found := g.ASNs[asn]; !found {
		as := g.NewNode("AS")
		as.Properties["asn"] = strconv.Itoa(asn)
		as.Properties["desc"] = desc
		g.Lock()
		g.ASNs[asn] = as
		g.Unlock()
	}
	as := g.ASNs[asn].idx
	g.NewEdge(as, n, "HAS_PREFIX")
	return nil
}

func (g *Graph) GetNewOutput() []*core.AmassOutput {
	var domains []string
	var dNodes []*Node
	var results []*core.AmassOutput

	g.Lock()
	for d, n := range g.Domains {
		domains = append(domains, d)
		dNodes = append(dNodes, n)
	}
	g.Unlock()

	for idx, domain := range domains {
		output := g.findSubdomainOutput(dNodes[idx])

		for _, o := range output {
			o.Domain = domain
		}

		results = append(results, output...)
	}
	return results
}

func (g *Graph) findSubdomainOutput(domain *Node) []*core.AmassOutput {
	var output []*core.AmassOutput

	if o := g.buildSubdomainOutput(domain); o != nil {
		output = append(output, o)
	}

	domain.Lock()
	edges := domain.Edges
	domain.Unlock()
	for _, idx := range edges {
		edge := g.Edges[idx]
		if edge.Label != "ROOT_OF" {
			continue
		}

		n := g.Nodes[edge.To]
		if o := g.buildSubdomainOutput(n); o != nil {
			output = append(output, o)
		}

		for cname := n; ; {
			prev := cname
			cname.Lock()
			cEdges := cname.Edges
			cname.Unlock()

			for _, i := range cEdges {
				e := g.Edges[i]
				if e.Label == "CNAME_TO" {
					cname = g.Nodes[e.To]
					break
				}
			}

			if cname == prev {
				break
			}

			if o := g.buildSubdomainOutput(cname); o != nil {
				output = append(output, o)
			}
		}
	}
	return output
}

func (g *Graph) buildSubdomainOutput(sub *Node) *core.AmassOutput {
	sub.Lock()
	_, ok := sub.Properties["sent"]
	sub.Unlock()
	if ok {
		return nil
	}

	output := &core.AmassOutput{
		Name:   sub.Properties["name"],
		Tag:    sub.Properties["tag"],
		Source: sub.Properties["source"],
	}

	t := core.TypeNorm
	if sub.Labels[0] != "NS" && sub.Labels[0] != "MX" {
		labels := strings.Split(output.Name, ".")

		if WebRegex.FindString(labels[0]) != "" {
			t = core.TypeWeb
		}
	} else {
		if sub.Labels[0] == "NS" {
			t = core.TypeNS
		} else if sub.Labels[0] == "MX" {
			t = core.TypeMX
		}
	}
	output.Type = t

	cname := g.traverseCNAME(sub)

	var addrs []*Node

	cname.Lock()
	edges := cname.Edges
	cname.Unlock()
	for _, idx := range edges {
		edge := g.Edges[idx]
		if edge.Label == "A_TO" || edge.Label == "AAAA_TO" {
			addrs = append(addrs, g.Nodes[edge.To])
		}
	}

	if len(addrs) == 0 {
		return nil
	}

	for _, addr := range addrs {
		if i := g.obtainInfrastructureData(addr); i != nil {
			output.Addresses = append(output.Addresses, *i)
		}
	}

	if len(output.Addresses) == 0 {
		return nil
	}

	sub.Lock()
	sub.Properties["sent"] = "yes"
	sub.Unlock()
	return output
}

func (g *Graph) traverseCNAME(sub *Node) *Node {
	cname := sub
	for {
		prev := cname

		cname.Lock()
		edges := cname.Edges
		cname.Unlock()
		for _, idx := range edges {
			edge := g.Edges[idx]
			if edge.Label == "CNAME_TO" {
				cname = g.Nodes[edge.To]
				break
			}
		}

		if cname == prev {
			break
		}
	}
	return cname
}

func (g *Graph) obtainInfrastructureData(addr *Node) *core.AmassAddressInfo {
	infr := &core.AmassAddressInfo{Address: net.ParseIP(addr.Properties["addr"])}

	var nb *Node

	addr.Lock()
	edges := addr.Edges
	addr.Unlock()
	for _, idx := range edges {
		edge := g.Edges[idx]
		if edge.Label == "CONTAINS" {
			nb = g.Nodes[edge.From]
			break
		}
	}
	if nb == nil {
		return nil
	}

	_, infr.Netblock, _ = net.ParseCIDR(nb.Properties["cidr"])

	nb.Lock()
	edges = nb.Edges
	nb.Unlock()
	var as *Node
	for _, idx := range edges {
		edge := g.Edges[idx]
		if edge.Label == "HAS_PREFIX" {
			as = g.Nodes[edge.From]
			break
		}
	}
	if as == nil {
		return nil
	}

	infr.ASN, _ = strconv.Atoi(as.Properties["asn"])
	infr.Description = as.Properties["desc"]
	return infr
}
