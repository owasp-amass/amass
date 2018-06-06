// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strconv"
	"sync"
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

func (g *Graph) insertDomain(domain, tag, source string) {
	g.Lock()
	defer g.Unlock()

	if _, found := g.Domains[domain]; found {
		return
	}

	d := g.NewNode("Domain")
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

	if _, found := g.Subdomains[target]; !found {
		sub := g.NewNode("NS")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		sub.Labels = append(sub.Labels, "Subdomain")
		g.Subdomains[target] = sub
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

	if _, found := g.Subdomains[target]; !found {
		sub := g.NewNode("MX")
		sub.Properties["name"] = target
		sub.Properties["tag"] = tag
		sub.Properties["source"] = source
		sub.Labels = append(sub.Labels, "Subdomain")
		g.Subdomains[target] = sub
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

const HTMLStart string = `<!doctype html>
<html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF8">
  <title>Amass Internet Satellite Imagery</title>

  <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.js"></script>
  <link type="text/css" rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/vis/4.21.0/vis.min.css">

  <style type="text/css">
    #thenetwork {
      width: 1200px;
      height: 800px;
      border: 1px solid lightgray;
    }
  </style>
  
</head>

<body>

<h2>DNS and Network Infrastructure Enumeration</h2>

<div id="thenetwork"></div>

<script type="text/javascript">
  var network;

  function redrawAll() {
    var container = document.getElementById('thenetwork');
    var options = {
    nodes: {
      shape: 'dot',
      size: 25,
      color: {
        border: 'rgb(23,32,42)'
      },
      font: {
    	size: 12,
    	face: 'Tahoma',
    	align: 'center'
      }
    },
    edges: {
      color: {
        color: 'rgb(166,172,175)',
        hover: 'black'
      },
      font: {
        color: 'rgb(166,172,175)',
        size: 12,
        align: 'middle'
      },
      width: 0.15,
      hoverWidth: 0.5
    },
    interaction: {
      hover: true,
      tooltipDelay: 200,
      zoomView: true
    },
    physics: {
      forceAtlas2Based: {
        gravitationalConstant: -26,
        centralGravity: 0.005,
        springLength: 230,
        springConstant: 0.18
      },
      maxVelocity: 50,
      solver: 'forceAtlas2Based',
      timestep: 0.2,
      stabilization: {iterations: 50}
    }
  };
`

const HTMLEnd string = `
    var data = {nodes: nodes, edges: edges};

    network = new vis.Network(container, data, options);
  }

  redrawAll()

</script>

</body>
</html>
`

func (g *Graph) ToVisjs() string {
	nodes := "var nodes = [\n"
	for idx, node := range g.nodes {
		idxStr := strconv.Itoa(idx + 1)

		switch node.Labels[0] {
		case "Subdomain":
			nodes += "{id: " + idxStr + ", title: 'Subdomain: " + node.Properties["name"] +
				"', color: {background: 'green'}},\n"
		case "Domain":
			nodes += "{id: " + idxStr + ", title: 'Domain: " + node.Properties["name"] +
				"', color: {background: 'red'}},\n"
		case "IPAddress":
			nodes += "{id: " + idxStr + ", title: 'IP: " + node.Properties["addr"] +
				"', color: {background: 'orange'}},\n"
		case "PTR":
			nodes += "{id: " + idxStr + ", title: 'PTR: " + node.Properties["name"] +
				"', color: {background: 'yellow'}},\n"
		case "NS":
			nodes += "{id: " + idxStr + ", title: 'NS: " + node.Properties["name"] +
				"', color: {background: 'cyan'}},\n"
		case "MX":
			nodes += "{id: " + idxStr + ", title: 'MX: " + node.Properties["name"] +
				"', color: {background: 'purple'}},\n"
		case "Netblock":
			nodes += "{id: " + idxStr + ", title: 'Netblock: " + node.Properties["cidr"] +
				"', color: {background: 'pink'}},\n"
		case "AS":
			nodes += "{id: " + idxStr + ", title: 'ASN: " +
				node.Properties["asn"] + ", Desc: " + node.Properties["desc"] +
				"', color: {background: 'blue'}},\n"
		}

	}
	nodes += "];\n"

	edges := "var edges = [\n"
	for _, edge := range g.edges {
		from := strconv.Itoa(edge.From + 1)
		to := strconv.Itoa(edge.To + 1)
		edges += "{from: " + from + ", to: " + to + ", title: '" + edge.Label + "'},\n"
	}
	edges += "];\n"

	return HTMLStart + nodes + edges + HTMLEnd
}
