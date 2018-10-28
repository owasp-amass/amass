// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"fmt"
	"net"
	"strconv"
	"sync"

	"github.com/OWASP/Amass/amass/utils/viz"
)

type Edge struct {
	From, To int
	Label    string
	idx      int
}

type Node struct {
	sync.Mutex
	Labels     []string
	Properties map[string]string
	edges      []int
	idx        int
}

func (n *Node) Edges() []int {
	n.Lock()
	defer n.Unlock()

	return n.edges
}

func (n *Node) AddEdge(e int) {
	n.Lock()
	defer n.Unlock()

	n.edges = append(n.edges, e)
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

func (g *Graph) String() string {
	return "Amass Graph"
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

func (g *Graph) DomainNode(domain string) *Node {
	g.Lock()
	defer g.Unlock()

	if domain == "" {
		return nil
	}
	return g.Domains[domain]
}

func (g *Graph) SubdomainNode(sub string) *Node {
	g.Lock()
	defer g.Unlock()

	if sub == "" {
		return nil
	}
	return g.Subdomains[sub]
}

func (g *Graph) CNAMENode(sub string) *Node {
	n := g.SubdomainNode(sub)
	if n == nil {
		return nil
	}

	for _, edgeIdx := range n.edges {
		edge := g.Edges[edgeIdx]
		if edge.From == n.idx && edge.Label == "CNAME_TO" {
			return n
		}
	}
	return nil
}

func (g *Graph) AddressNode(addr string) *Node {
	g.Lock()
	defer g.Unlock()

	if addr == "" {
		return nil
	}
	return g.Addresses[addr]
}

func (g *Graph) PTRNode(ptr string) *Node {
	g.Lock()
	defer g.Unlock()

	if ptr == "" {
		return nil
	}
	return g.PTRs[ptr]
}

func (g *Graph) NetblockNode(nb string) *Node {
	g.Lock()
	defer g.Unlock()

	if nb == "" {
		return nil
	}
	return g.Netblocks[nb]
}

func (g *Graph) ASNNode(asn int) *Node {
	g.Lock()
	defer g.Unlock()

	if asn == 0 {
		return nil
	}
	return g.ASNs[asn]
}

func (g *Graph) NewEdge(from, to int, label string) *Edge {
	g.Lock()
	defer g.Unlock()

	// Do not insert duplicate edges
	for _, idx := range g.Nodes[from].Edges() {
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
	g.Nodes[from].AddEdge(e.idx)
	g.Nodes[to].AddEdge(e.idx)
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

func (g *Graph) InsertSubdomain(name, domain, tag, source string) {
	if g.SubdomainNode(name) != nil {
		return
	}

	sub := g.NewNode("Subdomain")
	sub.Properties["name"] = name
	sub.Properties["tag"] = tag
	sub.Properties["source"] = source

	g.Lock()
	g.Subdomains[name] = sub
	g.Unlock()

	if d := g.DomainNode(domain); d != nil {
		if s := g.SubdomainNode(name); s != nil {
			g.NewEdge(d.idx, s.idx, "ROOT_OF")
		}
	}
}

func (g *Graph) InsertDomain(domain, tag, source string) error {
	if g.DomainNode(domain) != nil {
		return nil
	}

	if d := g.SubdomainNode(domain); d == nil {
		d = g.NewNode("Domain")
		if d == nil {
			return fmt.Errorf("Failed to create new domain node for %s", domain)
		}
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
		g.InsertSubdomain(name, domain, tag, source)
	}
	if target != tdomain {
		g.InsertSubdomain(target, tdomain, tag, source)
	}

	s := g.SubdomainNode(name)
	if s == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", name)
	}

	t := g.SubdomainNode(target)
	if t == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", target)
	}

	g.NewEdge(s.idx, t.idx, "CNAME_TO")
	return nil
}

func (g *Graph) InsertA(name, domain, addr, tag, source string) error {
	if name != domain {
		g.InsertSubdomain(name, domain, tag, source)
	}

	a := g.AddressNode(addr)
	if a == nil {
		a = g.NewNode("IPAddress")
		if a != nil {
			a.Properties["addr"] = addr
			a.Properties["type"] = "IPv4"
			g.Lock()
			g.Addresses[addr] = a
			g.Unlock()
		}
	}

	if s := g.SubdomainNode(name); s != nil && a != nil {
		g.NewEdge(s.idx, a.idx, "A_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the A_TO edge between %s and %s", addr, name)
}

func (g *Graph) InsertAAAA(name, domain, addr, tag, source string) error {
	if name != domain {
		g.InsertSubdomain(name, domain, tag, source)
	}

	a := g.AddressNode(addr)
	if a == nil {
		a = g.NewNode("IPAddress")
		if a != nil {
			a.Properties["addr"] = addr
			a.Properties["type"] = "IPv6"
			g.Lock()
			g.Addresses[addr] = a
			g.Unlock()
		}
	}

	if s := g.SubdomainNode(name); s != nil && a != nil {
		g.NewEdge(s.idx, a.idx, "AAAA_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the AAAA_TO edge between %s and %s", addr, name)
}

func (g *Graph) InsertPTR(name, domain, target, tag, source string) error {
	if target != domain {
		g.InsertSubdomain(target, domain, tag, source)
	}

	ptr := g.PTRNode(name)
	if ptr == nil {
		ptr = g.NewNode("PTR")
		if ptr != nil {
			ptr.Properties["name"] = name
			g.Lock()
			g.PTRs[name] = ptr
			g.Unlock()
		}
	}

	if s := g.SubdomainNode(target); s != nil && ptr != nil {
		g.NewEdge(ptr.idx, s.idx, "PTR_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the PTR_TO edge between %s and %s", name, target)
}

func (g *Graph) InsertSRV(name, domain, service, target, tag, source string) error {
	if name != domain {
		g.InsertSubdomain(name, domain, tag, source)
	}
	g.InsertSubdomain(service, domain, tag, source)
	g.InsertSubdomain(target, domain, tag, source)

	d := g.DomainNode(domain)
	if d == nil {
		return fmt.Errorf("Failed to obtain a reference to the domain node for %s", domain)
	}

	sub := g.SubdomainNode(name)
	if sub == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", name)
	}

	t := g.SubdomainNode(target)
	if t == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", target)
	}

	srv := g.SubdomainNode(service)
	if srv == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", service)
	}
	g.NewEdge(d.idx, srv.idx, "ROOT_OF")
	g.NewEdge(srv.idx, sub.idx, "SERVICE_FOR")
	g.NewEdge(srv.idx, t.idx, "SRV_TO")
	return nil
}

func (g *Graph) InsertNS(name, domain, target, tdomain, tag, source string) error {
	g.InsertSubdomain(name, domain, tag, source)

	ns := g.SubdomainNode(target)
	if ns == nil {
		ns = g.NewNode("NS")
		if ns != nil {
			ns.Properties["name"] = target
			ns.Properties["tag"] = tag
			ns.Properties["source"] = source
			ns.Labels = append(ns.Labels, "Subdomain")
			g.Lock()
			g.Subdomains[target] = ns
			g.Unlock()
		}
	} else {
		ns.Labels = []string{"NS", "Subdomain"}
	}

	if target != tdomain {
		if td := g.DomainNode(tdomain); td != nil && ns != nil {
			g.NewEdge(td.idx, ns.idx, "ROOT_OF")
		} else {
			return fmt.Errorf("Failed to insert the ROOT_OF edge between %s and %s", tdomain, target)
		}
	}

	if s := g.SubdomainNode(name); s != nil && ns != nil {
		g.NewEdge(s.idx, ns.idx, "NS_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the NS_TO edge between %s and %s", target, name)
}

func (g *Graph) InsertMX(name, domain, target, tdomain, tag, source string) error {
	g.InsertSubdomain(name, domain, tag, source)

	mx := g.SubdomainNode(target)
	if mx == nil {
		mx = g.NewNode("MX")
		if mx != nil {
			mx.Properties["name"] = target
			mx.Properties["tag"] = tag
			mx.Properties["source"] = source
			mx.Labels = append(mx.Labels, "Subdomain")
			g.Lock()
			g.Subdomains[target] = mx
			g.Unlock()
		}
	} else {
		mx.Labels = []string{"MX", "Subdomain"}
	}

	if target != tdomain {
		if td := g.DomainNode(tdomain); td != nil && mx != nil {
			g.NewEdge(td.idx, mx.idx, "ROOT_OF")
		} else {
			return fmt.Errorf("Failed to insert the ROOT_OF edge between %s and %s", tdomain, target)
		}
	}

	if s := g.SubdomainNode(name); s != nil && mx != nil {
		g.NewEdge(s.idx, mx.idx, "MX_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the MX_TO edge between %s and %s", target, name)
}

func (g *Graph) InsertInfrastructure(addr string, asn int, cidr *net.IPNet, desc string) error {
	str := cidr.String()
	nb := g.NetblockNode(str)
	if nb == nil {
		nb = g.NewNode("Netblock")
		if nb != nil {
			nb.Properties["cidr"] = str
			g.Lock()
			g.Netblocks[str] = nb
			g.Unlock()
		}
	}

	if ip := g.AddressNode(addr); nb != nil && ip != nil {
		g.NewEdge(nb.idx, ip.idx, "CONTAINS")
	} else {
		return fmt.Errorf("Failed to insert the CONTAINS edge between %s and %s", str, addr)
	}

	a := g.ASNNode(asn)
	if a == nil {
		a = g.NewNode("AS")
		if a != nil {
			a.Properties["asn"] = strconv.Itoa(asn)
			a.Properties["desc"] = desc
			g.Lock()
			g.ASNs[asn] = a
			g.Unlock()
		}
	}

	if a == nil {
		return fmt.Errorf("Failed to insert the HAS_PREFIX edge between AS%d and %s", asn, str)
	}
	g.NewEdge(a.idx, nb.idx, "HAS_PREFIX")
	return nil
}

func (g *Graph) GetNewOutput() []*AmassOutput {
	var domains []string
	var dNodes []*Node
	var results []*AmassOutput

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

func (g *Graph) findSubdomainOutput(domain *Node) []*AmassOutput {
	var output []*AmassOutput

	if o := g.buildSubdomainOutput(domain); o != nil {
		output = append(output, o)
	}

	for _, idx := range domain.Edges() {
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

			for _, i := range cname.Edges() {
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

func (g *Graph) buildSubdomainOutput(sub *Node) *AmassOutput {
	sub.Lock()
	_, ok := sub.Properties["sent"]
	sub.Unlock()
	if ok {
		return nil
	}

	output := &AmassOutput{
		Name:   sub.Properties["name"],
		Tag:    sub.Properties["tag"],
		Source: sub.Properties["source"],
	}

	var addrs []*Node
	cname := g.traverseCNAME(sub)
	for _, idx := range cname.Edges() {
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

		for _, idx := range cname.Edges() {
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

func (g *Graph) obtainInfrastructureData(addr *Node) *AmassAddressInfo {
	infr := &AmassAddressInfo{Address: net.ParseIP(addr.Properties["addr"])}

	var nb *Node

	for _, idx := range addr.Edges() {
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

	var as *Node
	for _, idx := range nb.Edges() {
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
