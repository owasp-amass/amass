// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"io"
	"text/template"

	oam "github.com/owasp-amass/open-asset-model"
)

const d3Template = `
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <title>OWASP Amass Network Mapping</title>
    <script src="https://d3js.org/d3.v4.min.js"></script>
    <style>
        div#tooltip {
            position: absolute;        
            display: inline-block;
            padding: 10px;
            font-family: 'Open Sans' sans-serif;
            color: #000;
            background-color: #fff;
            border: 1px solid #999;
            border-radius: 2px;
            pointer-events: none;
            opacity: 0;
            z-index: 1;
        }
    </style>
</head>
<body>
    <div id="graphDiv"></div>
    <div id="tooltip"></div>

<script>
/* global d3 */

var graph = {
    nodes: [
    {{ range .Nodes }}
        {id: {{.ID }}, num: {{ .Num }}, label: "{{ .Label }}", color: "{{ .Color }}" },
    {{ end }}
    ],
    edges: [
    {{ range .Edges }}
        {source: {{ .Source }}, target: {{ .Destination }}, label: "{{ .Label }}" },
    {{ end }}
    ]
};

var graphWidth = window.innerWidth,
    graphHeight = window.innerHeight;

var graphCanvas = d3.select('#graphDiv')
    .append('canvas')
    .classed('mainCanvas', true)
    .attr('width', graphWidth + 'px')
    .attr('height', graphHeight + 'px')
    .node();

var ctx = graphCanvas.getContext('2d');

var div = d3.select("body").append("div")
    .attr("class", "tooltip")
    .style("opacity", 0);

var r = 9,
    max = {{ .MaxNum }},
    simulation = d3.forceSimulation()
        .nodes(graph.nodes)
        .force("link", d3.forceLink()
            .links(graph.edges)
            .distance(nodeLinkDistance)
            .strength(nodeLinkStrength)
            .id(function(d) { return d.id; }))
        .force("charge", d3.forceManyBody()
            .strength(nodeChargeStrength)
            .distanceMax(graphWidth))
        .force("collide", d3.forceCollide()
            .radius(nodeCollideRadius))
        .force("center", d3.forceCenter(graphWidth / 2, graphHeight / 2))
        .on("tick", update),
    transform = d3.zoomIdentity;

d3.select(graphCanvas)
    .call(d3.drag()
        .container(graphCanvas)
        .subject(dragsubject)
        .on("start", dragstarted)
        .on("drag", dragged)
        .on("end", dragended))
    .call(d3.zoom().scaleExtent([1 / 10, 8]).on("zoom", zoomed));

function nodePercent(n) {
    return n.num / max;
}

function nodeRadius(n) {
    var p = nodePercent(n);

    if (p > 0.1 && p < 0.5) {
        p = p * 2;
    }
    if (p < 0.1) {
        p = 0.1;
    }
    return (1 * r) + ((3 * r) * p);
}

function nodeCollideRadius(n) {
    return nodeRadius(n) * 2.5;
}

function nodeLinkDistance(e) {
    var n1 = graph.nodes[e.source.id],
        n2 = graph.nodes[e.target.id];

    var avg = (nodePercent(n1) + nodePercent(n2)) / 2;

    if (avg > 0.7) {
        avg = 0.7;
    }
    if (avg < 0.5) {
        avg = 0.5;
    }
    return 100 * avg;
}

function nodeLinkStrength(e) {
    var n1 = graph.nodes[e.source.id],
        n2 = graph.nodes[e.target.id];

    var fp,
        p1 = nodePercent(n1),
        p2 = nodePercent(n2);

    if (p1 > p2) {
        fp = p1;
    } else {
        fp = p2;
    }

    if (fp > 0.7) {
        fp = 0.7;
    }
    if (fp < 0.5) {
        fp = 0.5;
    }
    return 1 - (1 * fp);
}

function nodeChargeStrength(n) {
    return -300 + (-50 * nodePercent(n));
}

function zoomed() {
    transform = d3.event.transform;
    update()
}

function update() {
    ctx.save();
    ctx.clearRect(0, 0, graphWidth, graphHeight);
    ctx.translate(transform.x, transform.y);
    ctx.scale(transform.k, transform.k);

    graph.edges.forEach(drawEdge);
    graph.nodes.forEach(drawNode);

    if (closeNode) {
        d3.select('#tooltip')
            .style('opacity', 0.8)
            .style('top', transform.applyY(closeNode.y) + 5 + 'px')
            .style('left', transform.applyX(closeNode.x) + 5 + 'px')
            .html(closeNode.label);
    }  else {
        d3.select('#tooltip')
            .style('opacity', 0);
    }

    ctx.restore();
}

function drawNode(d) {
    var size = nodeRadius(d);

    ctx.beginPath();
    ctx.fillStyle = d.color;
    ctx.moveTo(d.x, d.y);
    ctx.arc(d.x, d.y, size, 0, 2 * Math.PI);
    ctx.strokeStyle = "#333333";
    ctx.stroke();
    ctx.fill();
}

function drawEdge(e) {
    var dx = e.target.x - e.source.x,
        dy = e.target.y - e.source.y,
        align = 'center';

    ctx.beginPath()
    ctx.moveTo(e.source.x, e.source.y);
    ctx.lineTo(e.target.x, e.target.y);
    ctx.strokeStyle = "#aaa";
    ctx.stroke();

    var pad = 1/2;

    ctx.save();
    ctx.textAlign = align
    ctx.translate(e.source.x + dx * pad, e.source.y + dy * pad);

    if (dx < 0) {
        ctx.rotate(Math.atan2(dy, dx) - Math.PI);
    } else {
        ctx.rotate(Math.atan2(dy, dx));
    }

    ctx.fillStyle = "#aaa";
    ctx.fillText(e.label, 0, 0);
    ctx.restore();
}

var closeNode;
d3.select("canvas").on("mousemove", function(d) {
    var p = d3.mouse(this);

    closeNode = findNode(p[0], p[1]);
    update();
})

function findNode(x, y) {
    var i,
        newx = transform.invertX(x),
        newy = transform.invertY(y),
        dx,
        dy,
        radius;

    for (i = graph.nodes.length - 1; i >= 0; --i) {
        node = graph.nodes[i];
        dx = newx - node.x;
        dy = newy - node.y;
        radius = nodeRadius(node);

        if (dx * dx + dy * dy < radius * radius) {
            return node;
        }
    }
}

function dragsubject() {
    var node = findNode(d3.event.x, d3.event.y);

    node.x = transform.applyX(node.x);
    node.y = transform.applyY(node.y);
    return node
}

function dragstarted() {
    if (!d3.event.active) simulation.alphaTarget(0.3).restart();
    d3.event.subject.fx = transform.invertX(d3.event.subject.x);
    d3.event.subject.fy = transform.invertY(d3.event.subject.y);
}

function dragged() {
    d3.event.subject.fx = transform.invertX(d3.event.x);
    d3.event.subject.fy = transform.invertY(d3.event.y);
}

function dragended() {
    if (!d3.event.active) simulation.alphaTarget(0);
    d3.event.subject.fx = null;
    d3.event.subject.fy = null;
}

update();

</script>
</body>
</html>
`

type d3Edge struct {
	Source      int
	Destination int
	Label       string
}

type d3Node struct {
	ID    int
	Num   int
	Label string
	Color string
}

type d3Graph struct {
	Name   string
	MaxNum int
	Nodes  []d3Node
	Edges  []d3Edge
}

// WriteD3Data generates a HTML file that displays the Amass graph using D3.
func WriteD3Data(output io.Writer, nodes []Node, edges []Edge) error {
	colors := map[string]string{
		string(oam.Account):          "chocolate",
		string(oam.AutnumRecord):     "yellow",
		string(oam.AutonomousSystem): "blue",
		string(oam.ContactRecord):    "cornsilk",
		string(oam.DomainRecord):     "yellow",
		string(oam.File):             "azure",
		string(oam.FQDN):             "green",
		string(oam.FundsTransfer):    "red",
		string(oam.Identifier):       "chocolate",
		string(oam.IPAddress):        "orange",
		string(oam.IPNetRecord):      "yellow",
		string(oam.Location):         "darkgray",
		string(oam.Netblock):         "pink",
		string(oam.Organization):     "aqua",
		string(oam.Person):           "bisque",
		string(oam.Phone):            "coral",
		string(oam.Product):          "darkslategrey",
		string(oam.ProductRelease):   "darkslategrey",
		string(oam.Service):          "darkslategrey",
		string(oam.TLSCertificate):   "deeppink",
		string(oam.URL):              "azure",
	}

	graph := &d3Graph{Name: "OWASP Amass - Attack Surface Mapping"}

	for idx, node := range nodes {
		graph.Nodes = append(graph.Nodes, d3Node{
			ID:    idx,
			Label: node.Title,
			Color: colors[node.Type],
		})
	}

	for _, edge := range edges {
		graph.Edges = append(graph.Edges, d3Edge{
			Source:      edge.From,
			Destination: edge.To,
			Label:       edge.Title,
		})
		graph.Nodes[edge.From].Num++
		graph.Nodes[edge.To].Num++
	}

	for _, node := range graph.Nodes {
		if node.Num > graph.MaxNum {
			graph.MaxNum = node.Num
		}
	}

	t := template.Must(template.New("graph").Parse(d3Template))
	return t.Execute(output, graph)
}
