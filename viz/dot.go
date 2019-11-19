// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
	"io"
	"strconv"
	"text/template"
)

const dotTemplate = `
digraph {{ .Name }} {
{{ range .Nodes }}
        node [label="{{ .Label }}",color="{{ .Color }}",type="{{ .Type }}",source="{{ .Source }}"]; n{{ .ID }};
{{ end }}

{{ range .Edges }}
        n{{ .Source }} -> n{{ .Destination }} [label="{{ .Label }}"];
{{ end }}
}
`

type dotEdge struct {
	Source      string
	Destination string
	Label       string
}

type dotNode struct {
	ID     string
	Label  string
	Color  string
	Type   string
	Source string
}

type dotGraph struct {
	Name  string
	Nodes []dotNode
	Edges []dotEdge
}

// WriteDOTData generates a DOT file to display the Amass graph.
func WriteDOTData(output io.Writer, nodes []Node, edges []Edge) {
	colors := map[string]string{
		"subdomain": "green",
		"domain":    "red",
		"address":   "orange",
		"ptr":       "yellow",
		"ns":        "cyan",
		"mx":        "purple",
		"netblock":  "pink",
		"as":        "blue",
	}

	graph := &dotGraph{Name: "Amass"}

	for idx, node := range nodes {
		graph.Nodes = append(graph.Nodes, dotNode{
			ID:     strconv.Itoa(idx + 1),
			Label:  node.Label,
			Color:  colors[node.Type],
			Type:   node.Type,
			Source: node.Source,
		})
	}

	for _, edge := range edges {
		graph.Edges = append(graph.Edges, dotEdge{
			Source:      strconv.Itoa(edge.From + 1),
			Destination: strconv.Itoa(edge.To + 1),
			Label:       edge.Label,
		})
	}

	t := template.Must(template.New("graph").Parse(dotTemplate))
	t.Execute(output, graph)
}
