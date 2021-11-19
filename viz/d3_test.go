package viz

import (
	"bytes"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestWriteD3DataHappyPath(t *testing.T) {

	buf := bytes.NewBufferString("")
	err := WriteD3Data(buf, testNodes(), testEdges())
	assert.Nil(t, err)

	output := buf.String()
	assert.Equalf(t, expectedOutput, output, "Expected output to match")
}

const expectedOutput = `
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
    
        {id: 0, num: 1, label: "domain: owasp.org, Source: DNS", color: "red" },
    
        {id: 1, num: 1, label: "address: 205.251.199.98, Source: DNS", color: "orange" },
    
    ],
    edges: [
    
        {source: 0, target: 1, label: "a_record" },
    
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

var r = 5,
    max = 1,
    simulation = d3.forceSimulation()
        .nodes(graph.nodes)
        .force("link", d3.forceLink()
            .links(graph.edges)
            .distance(nodeLinkDistance)
            .strength(nodeLinkStrength)
            .id(function(d) { return d.id; }))
        .force("charge", d3.forceManyBody()
            .strength(nodeChargeStrength)
            .distanceMax(graphWidth *2))
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
    return (1.5 * r) + ((3 * r) * nodePercent(n));
}

function nodeCollideRadius(n) {
    return nodeRadius(n) + 1;
}

function nodeLinkDistance(e) {
    var n1 = graph.nodes[e.source.id],
        n2 = graph.nodes[e.target.id];

    var avg = (nodePercent(n1) + nodePercent(n2)) / 2;
    
    return 60 * avg;
}

function nodeLinkStrength(e) {
    var n1 = graph.nodes[e.source.id],
        n2 = graph.nodes[e.target.id];

    var avg = (nodePercent(n1) + nodePercent(n2)) / 2;

    return 1 - (1 * avg);
}

function nodeChargeStrength(n) {
    return -100 + (-300 * nodePercent(n));
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
