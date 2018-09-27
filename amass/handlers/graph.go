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

func (g *Graph) InsertSubdomain(name, tag, source string) {
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
}

func (g *Graph) InsertDomain(domain, tag, source string) error {
	if g.DomainNode(domain) != nil {
		return nil
	}

	if d := g.SubdomainNode(domain); d == nil {
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
		g.InsertSubdomain(name, tag, source)
		g.NewEdge(g.DomainNode(domain).idx, g.SubdomainNode(name).idx, "ROOT_OF")
	}

	if target != tdomain {
		g.InsertSubdomain(target, tag, source)
		g.NewEdge(g.DomainNode(tdomain).idx, g.SubdomainNode(target).idx, "ROOT_OF")
	}

	g.NewEdge(g.SubdomainNode(name).idx, g.SubdomainNode(target).idx, "CNAME_TO")
	return nil
}

func (g *Graph) InsertA(name, domain, addr, tag, source string) error {
	if name != domain {
		g.InsertSubdomain(name, tag, source)
		g.NewEdge(g.DomainNode(domain).idx, g.SubdomainNode(name).idx, "ROOT_OF")
	}

	if g.AddressNode(addr) == nil {
		a := g.NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv4"
		g.Lock()
		g.Addresses[addr] = a
		g.Unlock()
	}

	g.NewEdge(g.SubdomainNode(name).idx, g.AddressNode(addr).idx, "A_TO")
	return nil
}

func (g *Graph) InsertAAAA(name, domain, addr, tag, source string) error {
	if name != domain {
		g.InsertSubdomain(name, tag, source)
		g.NewEdge(g.DomainNode(domain).idx, g.SubdomainNode(name).idx, "ROOT_OF")
	}

	if g.AddressNode(addr) == nil {
		a := g.NewNode("IPAddress")
		a.Properties["addr"] = addr
		a.Properties["type"] = "IPv6"
		g.Lock()
		g.Addresses[addr] = a
		g.Unlock()
	}

	g.NewEdge(g.SubdomainNode(name).idx, g.AddressNode(addr).idx, "AAAA_TO")
	return nil
}

func (g *Graph) InsertPTR(name, domain, target, tag, source string) error {
	if target != domain {
		g.InsertSubdomain(target, tag, source)
		g.NewEdge(g.DomainNode(domain).idx, g.SubdomainNode(target).idx, "ROOT_OF")
	}

	if g.PTRNode(name) == nil {
		ptr := g.NewNode("PTR")
		ptr.Properties["name"] = name
		g.Lock()
		g.PTRs[name] = ptr
		g.Unlock()
	}

	g.NewEdge(g.PTRNode(name).idx, g.SubdomainNode(target).idx, "PTR_TO")
	return nil
}

func (g *Graph) InsertSRV(name, domain, service, target, tag, source string) error {
	if name != domain {
		g.InsertSubdomain(name, tag, source)
	}
	g.InsertSubdomain(service, tag, source)
	g.InsertSubdomain(target, tag, source)

	d := g.DomainNode(domain).idx
	sub := g.SubdomainNode(name).idx
	t := g.SubdomainNode(target).idx
	srv := g.SubdomainNode(service).idx

	g.NewEdge(d, srv, "ROOT_OF")
	g.NewEdge(srv, sub, "SERVICE_FOR")
	g.NewEdge(srv, t, "SRV_TO")
	return nil
}

func (g *Graph) InsertNS(name, domain, target, tdomain, tag, source string) error {
	g.InsertSubdomain(name, tag, source)

	if ns := g.SubdomainNode(target); ns == nil {
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
		g.NewEdge(g.DomainNode(tdomain).idx, g.SubdomainNode(target).idx, "ROOT_OF")
	}
	g.NewEdge(g.SubdomainNode(name).idx, g.SubdomainNode(target).idx, "NS_TO")
	return nil
}

func (g *Graph) InsertMX(name, domain, target, tdomain, tag, source string) error {
	g.InsertSubdomain(name, tag, source)

	if mx := g.SubdomainNode(target); mx == nil {
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
		g.NewEdge(g.DomainNode(tdomain).idx, g.SubdomainNode(target).idx, "ROOT_OF")
	}
	g.NewEdge(g.SubdomainNode(name).idx, g.SubdomainNode(target).idx, "MX_TO")
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

	n := g.NetblockNode(nb).idx
	g.NewEdge(n, g.AddressNode(addr).idx, "CONTAINS")

	if a := g.ASNNode(asn); a == nil {
		as := g.NewNode("AS")
		as.Properties["asn"] = strconv.Itoa(asn)
		as.Properties["desc"] = desc
		g.Lock()
		g.ASNs[asn] = as
		g.Unlock()
	}
	g.NewEdge(g.ASNNode(asn).idx, n, "HAS_PREFIX")
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

func (g *Graph) obtainInfrastructureData(addr *Node) *core.AmassAddressInfo {
	infr := &core.AmassAddressInfo{Address: net.ParseIP(addr.Properties["addr"])}

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
