// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package handlers

import (
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils/viz"
)

type edge struct {
	From, To int
	Label    string
	idx      int
}

type node struct {
	sync.Mutex
	Labels     []string
	Properties map[string]string
	edges      []int
	idx        int
}

// Edges safely returns all the edges connected to the node.
func (n *node) Edges() []int {
	n.Lock()
	defer n.Unlock()

	return n.edges
}

func (n *node) addEdge(e int) {
	n.Lock()
	defer n.Unlock()

	n.edges = append(n.edges, e)
}

// Graph is the object for managing a network infrastructure link graph.
type Graph struct {
	sync.Mutex
	domains    map[string]*node
	subdomains map[string]*node
	addresses  map[string]*node
	ptrs       map[string]*node
	netblocks  map[string]*node
	asns       map[int]*node
	nodes      []*node
	curNodeIdx int
	edges      []*edge
	curEdgeIdx int
}

// NewGraph returns an intialized Graph object.
func NewGraph() *Graph {
	return &Graph{
		domains:    make(map[string]*node),
		subdomains: make(map[string]*node),
		addresses:  make(map[string]*node),
		ptrs:       make(map[string]*node),
		netblocks:  make(map[string]*node),
		asns:       make(map[int]*node),
	}
}

// String implements the Amass data handler interface.
func (g *Graph) String() string {
	return "Amass Graph"
}

// Insert implements the Amass DataHandler interface.
func (g *Graph) Insert(data *DataOptsParams) error {
	var err error

	switch data.Type {
	case OptDomain:
		err = g.insertDomain(data)
	case OptSubdomain:
		err = g.insertSubdomain(data)
	case OptCNAME:
		err = g.insertCNAME(data)
	case OptA:
		err = g.insertA(data)
	case OptAAAA:
		err = g.insertAAAA(data)
	case OptPTR:
		err = g.insertPTR(data)
	case OptSRV:
		err = g.insertSRV(data)
	case OptNS:
		err = g.insertNS(data)
	case OptMX:
		err = g.insertMX(data)
	case OptInfrastructure:
		err = g.insertInfrastructure(data)
	}
	return err
}

func (g *Graph) newNode(label string) *node {
	g.Lock()
	defer g.Unlock()

	n := &node{
		Properties: make(map[string]string),
		idx:        g.curNodeIdx,
	}

	g.curNodeIdx++
	g.nodes = append(g.nodes, n)
	n.Labels = append(n.Labels, label)
	return n
}

func (g *Graph) domainNode(domain string) *node {
	g.Lock()
	defer g.Unlock()

	if domain == "" {
		return nil
	}
	return g.domains[domain]
}

func (g *Graph) subdomainNode(sub string) *node {
	g.Lock()
	defer g.Unlock()

	if sub == "" {
		return nil
	}
	return g.subdomains[sub]
}

// CNAMENode returns the Node for the subdomain name provided if it's a CNAME.
func (g *Graph) CNAMENode(sub string) bool {
	n := g.subdomainNode(sub)
	if n == nil {
		return false
	}

	for _, edgeIdx := range n.edges {
		e := g.edges[edgeIdx]
		if e.From == n.idx && e.Label == "CNAME_TO" {
			return true
		}
	}
	return false
}

func (g *Graph) addressNode(addr string) *node {
	g.Lock()
	defer g.Unlock()

	if addr == "" {
		return nil
	}
	return g.addresses[addr]
}

func (g *Graph) ptrNode(ptr string) *node {
	g.Lock()
	defer g.Unlock()

	if ptr == "" {
		return nil
	}
	return g.ptrs[ptr]
}

func (g *Graph) netblockNode(nb string) *node {
	g.Lock()
	defer g.Unlock()

	if nb == "" {
		return nil
	}
	return g.netblocks[nb]
}

func (g *Graph) asnNode(asn int) *node {
	g.Lock()
	defer g.Unlock()

	return g.asns[asn]
}

func (g *Graph) newEdge(from, to int, label string) *edge {
	g.Lock()
	defer g.Unlock()

	// Do not insert duplicate edges
	for _, idx := range g.nodes[from].Edges() {
		e := g.edges[idx]
		if e.Label == label && e.From == from && e.To == to {
			return nil
		}
	}

	e := &edge{
		From:  from,
		To:    to,
		Label: label,
		idx:   g.curEdgeIdx,
	}

	g.curEdgeIdx++
	g.nodes[from].addEdge(e.idx)
	g.nodes[to].addEdge(e.idx)
	g.edges = append(g.edges, e)
	return e
}

// VizData returns the current state of the Graph as viz package Nodes and Edges.
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

	for idx, n := range g.nodes {
		var label, title, source string
		t := n.Labels[0]

		switch t {
		case "Subdomain":
			label = n.Properties["name"]
			title = t + ": " + label
			source = n.Properties["source"]
		case "Domain":
			label = n.Properties["name"]
			title = t + ": " + label
			source = n.Properties["source"]
		case "IPAddress":
			label = n.Properties["addr"]
			title = t + ": " + label
		case "PTR":
			label = n.Properties["name"]
			title = t + ": " + label
		case "NS":
			label = n.Properties["name"]
			title = t + ": " + label
			source = n.Properties["source"]
		case "MX":
			label = n.Properties["name"]
			title = t + ": " + label
			source = n.Properties["source"]
		case "Netblock":
			label = n.Properties["cidr"]
			title = t + ": " + label
		case "AS":
			label = n.Properties["asn"]
			title = t + ": " + label + ", Desc: " + n.Properties["desc"]
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

func (g *Graph) insertDomain(data *DataOptsParams) error {
	if g.domainNode(data.Domain) != nil {
		return nil
	}

	if d := g.subdomainNode(data.Domain); d == nil {
		d = g.newNode("Domain")
		if d == nil {
			return fmt.Errorf("Failed to create new domain node for %s", data.Domain)
		}
		d.Labels = append(d.Labels, "Subdomain")
		d.Properties["name"] = data.Domain
		d.Properties["tag"] = data.Tag
		d.Properties["source"] = data.Source
		g.Lock()
		g.domains[data.Domain] = d
		g.subdomains[data.Domain] = d
		g.Unlock()
	} else {
		d.Labels = []string{"Domain", "Subdomain"}
		g.Lock()
		g.domains[data.Domain] = d
		g.Unlock()
	}
	return nil
}

func (g *Graph) insertSubdomain(data *DataOptsParams) error {
	if g.subdomainNode(data.Name) != nil {
		return nil
	}

	sub := g.newNode("Subdomain")
	sub.Properties["name"] = data.Name
	sub.Properties["tag"] = data.Tag
	sub.Properties["source"] = data.Source

	g.Lock()
	g.subdomains[data.Name] = sub
	g.Unlock()

	if d := g.domainNode(data.Domain); d != nil {
		if s := g.subdomainNode(data.Name); s != nil {
			g.newEdge(d.idx, s.idx, "ROOT_OF")
		}
	}
	return nil
}

func (g *Graph) insertCNAME(data *DataOptsParams) error {
	if data.Name != data.Domain {
		g.insertSubdomain(data)
	}
	if data.TargetName != data.TargetDomain {
		g.insertSubdomain(&DataOptsParams{
			Timestamp: data.Timestamp,
			Type:      OptSubdomain,
			Name:      data.TargetName,
			Domain:    data.TargetDomain,
			Tag:       data.Tag,
			Source:    data.Source,
		})
	}

	s := g.subdomainNode(data.Name)
	if s == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", data.Name)
	}

	t := g.subdomainNode(data.TargetName)
	if t == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", data.TargetName)
	}

	g.newEdge(s.idx, t.idx, "CNAME_TO")
	return nil
}

func (g *Graph) insertA(data *DataOptsParams) error {
	if data.Name != data.Domain {
		g.insertSubdomain(data)
	}

	a := g.addressNode(data.Address)
	if a == nil {
		a = g.newNode("IPAddress")
		if a != nil {
			a.Properties["addr"] = data.Address
			a.Properties["type"] = "IPv4"
			g.Lock()
			g.addresses[data.Address] = a
			g.Unlock()
		}
	}

	if s := g.subdomainNode(data.Name); s != nil && a != nil {
		g.newEdge(s.idx, a.idx, "A_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the A_TO edge between %s and %s", data.Address, data.Name)
}

func (g *Graph) insertAAAA(data *DataOptsParams) error {
	if data.Name != data.Domain {
		g.insertSubdomain(data)
	}

	a := g.addressNode(data.Address)
	if a == nil {
		a = g.newNode("IPAddress")
		if a != nil {
			a.Properties["addr"] = data.Address
			a.Properties["type"] = "IPv6"
			g.Lock()
			g.addresses[data.Address] = a
			g.Unlock()
		}
	}

	if s := g.subdomainNode(data.Name); s != nil && a != nil {
		g.newEdge(s.idx, a.idx, "AAAA_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the AAAA_TO edge between %s and %s", data.Address, data.Name)
}

func (g *Graph) insertPTR(data *DataOptsParams) error {
	if data.TargetName != data.Domain {
		g.insertSubdomain(data)
	}

	ptr := g.ptrNode(data.Name)
	if ptr == nil {
		ptr = g.newNode("PTR")
		if ptr != nil {
			ptr.Properties["name"] = data.Name
			g.Lock()
			g.ptrs[data.Name] = ptr
			g.Unlock()
		}
	}

	if s := g.subdomainNode(data.TargetName); s != nil && ptr != nil {
		g.newEdge(ptr.idx, s.idx, "PTR_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the PTR_TO edge between %s and %s", data.Name, data.TargetName)
}

func (g *Graph) insertSRV(data *DataOptsParams) error {
	if data.Name != data.Domain {
		g.insertSubdomain(data)
	}
	g.insertSubdomain(&DataOptsParams{
		Timestamp: data.Timestamp,
		Name:      data.Service,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})
	g.insertSubdomain(&DataOptsParams{
		Timestamp: data.Timestamp,
		Name:      data.TargetName,
		Domain:    data.Domain,
		Tag:       data.Tag,
		Source:    data.Source,
	})

	d := g.domainNode(data.Domain)
	if d == nil {
		return fmt.Errorf("Failed to obtain a reference to the domain node for %s", data.Domain)
	}

	sub := g.subdomainNode(data.Name)
	if sub == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", data.Name)
	}

	t := g.subdomainNode(data.TargetName)
	if t == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", data.TargetName)
	}

	srv := g.subdomainNode(data.Service)
	if srv == nil {
		return fmt.Errorf("Failed to obtain a reference to the node for %s", data.Service)
	}
	g.newEdge(d.idx, srv.idx, "ROOT_OF")
	g.newEdge(srv.idx, sub.idx, "SERVICE_FOR")
	g.newEdge(srv.idx, t.idx, "SRV_TO")
	return nil
}

func (g *Graph) insertNS(data *DataOptsParams) error {
	g.insertSubdomain(data)

	ns := g.subdomainNode(data.TargetName)
	if ns == nil {
		ns = g.newNode("NS")
		if ns != nil {
			ns.Properties["name"] = data.TargetName
			ns.Properties["tag"] = data.Tag
			ns.Properties["source"] = data.Source
			ns.Labels = append(ns.Labels, "Subdomain")
			g.Lock()
			g.subdomains[data.TargetName] = ns
			g.Unlock()
		}
	} else {
		ns.Labels = []string{"NS", "Subdomain"}
	}

	if data.TargetName != data.TargetDomain {
		if td := g.domainNode(data.TargetDomain); td != nil && ns != nil {
			g.newEdge(td.idx, ns.idx, "ROOT_OF")
		} else {
			return fmt.Errorf("Failed to insert the ROOT_OF edge between %s and %s", data.TargetDomain, data.TargetName)
		}
	}

	if s := g.subdomainNode(data.Name); s != nil && ns != nil {
		g.newEdge(s.idx, ns.idx, "NS_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the NS_TO edge between %s and %s", data.TargetName, data.Name)
}

func (g *Graph) insertMX(data *DataOptsParams) error {
	g.insertSubdomain(data)

	mx := g.subdomainNode(data.TargetName)
	if mx == nil {
		mx = g.newNode("MX")
		if mx != nil {
			mx.Properties["name"] = data.TargetName
			mx.Properties["tag"] = data.Tag
			mx.Properties["source"] = data.Source
			mx.Labels = append(mx.Labels, "Subdomain")
			g.Lock()
			g.subdomains[data.TargetName] = mx
			g.Unlock()
		}
	} else {
		mx.Labels = []string{"MX", "Subdomain"}
	}

	if data.TargetName != data.TargetDomain {
		if td := g.domainNode(data.TargetDomain); td != nil && mx != nil {
			g.newEdge(td.idx, mx.idx, "ROOT_OF")
		} else {
			return fmt.Errorf("Failed to insert the ROOT_OF edge between %s and %s", data.TargetDomain, data.TargetName)
		}
	}

	if s := g.subdomainNode(data.Name); s != nil && mx != nil {
		g.newEdge(s.idx, mx.idx, "MX_TO")
		return nil
	}
	return fmt.Errorf("Failed to insert the MX_TO edge between %s and %s", data.TargetName, data.Name)
}

func (g *Graph) insertInfrastructure(data *DataOptsParams) error {
	nb := g.netblockNode(data.CIDR)
	if nb == nil {
		nb = g.newNode("Netblock")
		if nb != nil {
			nb.Properties["cidr"] = data.CIDR
			g.Lock()
			g.netblocks[data.CIDR] = nb
			g.Unlock()
		}
	}

	if ip := g.addressNode(data.Address); nb != nil && ip != nil {
		g.newEdge(nb.idx, ip.idx, "CONTAINS")
	} else {
		return fmt.Errorf("Failed to insert the CONTAINS edge between %s and %s", data.CIDR, data.Address)
	}

	a := g.asnNode(data.ASN)
	if a == nil {
		a = g.newNode("AS")
		if a != nil {
			a.Properties["asn"] = strconv.Itoa(data.ASN)
			a.Properties["desc"] = data.Description
			g.Lock()
			g.asns[data.ASN] = a
			g.Unlock()
		}
	}

	if a == nil {
		return fmt.Errorf("Failed to insert the HAS_PREFIX edge between AS%d and %s", data.ASN, data.CIDR)
	}
	g.newEdge(a.idx, nb.idx, "HAS_PREFIX")
	return nil
}

// GetNewOutput returns new findings within the enumeration Graph.
func (g *Graph) GetNewOutput() []*core.Output {
	var domains []string
	var dNodes []*node
	var results []*core.Output

	g.Lock()
	for d, n := range g.domains {
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

func (g *Graph) findSubdomainOutput(domain *node) []*core.Output {
	var output []*core.Output

	if o := g.buildSubdomainOutput(domain); o != nil {
		output = append(output, o)
	}

	for _, idx := range domain.Edges() {
		e := g.edges[idx]
		if e.Label != "ROOT_OF" {
			continue
		}

		n := g.nodes[e.To]
		if o := g.buildSubdomainOutput(n); o != nil {
			output = append(output, o)
		}

		for cname := n; ; {
			prev := cname
			for _, i := range cname.Edges() {
				e2 := g.edges[i]
				if e.Label == "CNAME_TO" {
					cname = g.nodes[e2.To]
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

func (g *Graph) buildSubdomainOutput(sub *node) *core.Output {
	sub.Lock()
	_, ok := sub.Properties["sent"]
	sub.Unlock()
	if ok {
		return nil
	}

	output := &core.Output{
		Name:   sub.Properties["name"],
		Tag:    sub.Properties["tag"],
		Source: sub.Properties["source"],
	}

	var addrs []*node
	cname := g.traverseCNAME(sub)
	for _, idx := range cname.Edges() {
		e := g.edges[idx]
		if e.Label == "A_TO" || e.Label == "AAAA_TO" {
			addrs = append(addrs, g.nodes[e.To])
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
	defer sub.Unlock()
	if _, started := sub.Properties["started"]; !started {
		sub.Properties["started"] = "yes"
		go func(n *node) {
			time.Sleep(5 * time.Second)
			n.Lock()
			n.Properties["finished"] = "yes"
			n.Unlock()
		}(sub)
		return nil
	}
	if _, finished := sub.Properties["finished"]; !finished {
		return nil
	}
	sub.Properties["sent"] = "yes"
	return output
}

func (g *Graph) traverseCNAME(sub *node) *node {
	cname := sub
	for {
		prev := cname
		for _, idx := range cname.Edges() {
			e := g.edges[idx]
			if e.Label == "CNAME_TO" || e.Label == "SRV_TO" {
				cname = g.nodes[e.To]
				break
			}
		}
		if cname == prev {
			break
		}
	}
	return cname
}

func (g *Graph) obtainInfrastructureData(addr *node) *core.AddressInfo {
	var nb *node
	infr := &core.AddressInfo{Address: net.ParseIP(addr.Properties["addr"])}

	for _, idx := range addr.Edges() {
		e := g.edges[idx]
		if e.Label == "CONTAINS" {
			nb = g.nodes[e.From]
			break
		}
	}
	if nb == nil {
		return nil
	}

	_, infr.Netblock, _ = net.ParseCIDR(nb.Properties["cidr"])

	var as *node
	for _, idx := range nb.Edges() {
		e := g.edges[idx]
		if e.Label == "HAS_PREFIX" {
			as = g.nodes[e.From]
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
