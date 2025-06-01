// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package viz

import (
	"io"
	"strconv"
	"text/template"
)

const dotTemplate = `
digraph "{{ .Name }}" {
	size = "7.5,10"; ranksep="2.5 equally"; ratio=auto;

{{ range .Nodes }}
        node [label="{{ .Label }}",color="{{ .Color }}",type="{{ .Type }}"]; n{{ .ID }};
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
	ID    string
	Label string
	Color string
	Type  string
}

type dotGraph struct {
	Name  string
	Nodes []dotNode
	Edges []dotEdge
}

// WriteDOTData generates a DOT file to display the Amass graph.
func WriteDOTData(output io.Writer, nodes []Node, edges []Edge) error {
	// TODO: Add more OAM types and colors
	colors := map[string]string{
		"FQDN":      "green",
		"domain":    "red",
		"IPAddress": "orange",
		"RIROrg":    "cyan",
		"Netblock":  "pink",
		"ASN":       "blue",
	}

	graph := &dotGraph{Name: "OWASP Amass Network Mapping"}

	for idx, node := range nodes {
		graph.Nodes = append(graph.Nodes, dotNode{
			ID:    strconv.Itoa(idx + 1),
			Label: node.Label,
			Color: colors[node.Type],
			Type:  node.Type,
		})
	}

	for _, edge := range edges {
		graph.Edges = append(graph.Edges, dotEdge{
			Source:      strconv.Itoa(edge.From + 1),
			Destination: strconv.Itoa(edge.To + 1),
			Label:       edge.Title,
		})
	}

	t := template.Must(template.New("graph").Parse(dotTemplate))
	return t.Execute(output, graph)
}
