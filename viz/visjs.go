// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
	"bufio"
	"io"
	"strconv"
)

const htmlStart string = `<!doctype html>
<html>
<head>
  <meta http-equiv="content-type" content="text/html; charset=UTF8">
  <title>OWASP Amass Network Mapping</title>

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

<h2>OWASP Amass Network Mapping</h2>

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

const htmlEnd string = `
    var data = {nodes: nodes, edges: edges};

    network = new vis.Network(container, data, options);
  }

  redrawAll()

</script>

</body>
</html>
`

// WriteVisjsData generates a HTML file that displays the Amass graph using Visjs.
func WriteVisjsData(output io.Writer, nodes []Node, edges []Edge) {
	bufwr := bufio.NewWriter(output)

	bufwr.WriteString(htmlStart)
	bufwr.Flush()

	nStr := "var nodes = [\n"
	for idx, node := range nodes {
		idxStr := strconv.Itoa(idx + 1)

		switch node.Type {
		case "subdomain":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				", Source: " + node.Source + "', color: {background: 'green'}},\n"
		case "domain":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				", Source: " + node.Source + "', color: {background: 'red'}},\n"
		case "address":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				"', color: {background: 'orange'}},\n"
		case "ptr":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				"', color: {background: 'yellow'}},\n"
		case "ns":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				", Source: " + node.Source + "', color: {background: 'cyan'}},\n"
		case "mx":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				", Source: " + node.Source + "', color: {background: 'purple'}},\n"
		case "netblock":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				"', color: {background: 'pink'}},\n"
		case "as":
			nStr += "{id: " + idxStr + ", title: '" + node.Title +
				"', color: {background: 'blue'}},\n"
		}

	}
	nStr += "];\n"
	bufwr.WriteString(nStr)
	bufwr.Flush()

	eStr := "var edges = [\n"
	for _, edge := range edges {
		from := strconv.Itoa(edge.From + 1)
		to := strconv.Itoa(edge.To + 1)
		eStr += "{from: " + from + ", to: " + to + ", title: '" + edge.Title + "'},\n"
	}
	eStr += "];\n"
	bufwr.WriteString(eStr)
	bufwr.Flush()

	bufwr.WriteString(htmlEnd)
	bufwr.Flush()
}
