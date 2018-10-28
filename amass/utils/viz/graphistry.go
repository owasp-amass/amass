// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
	"encoding/json"
	"io"
	"strconv"
	"time"
)

type graphistryBindings struct {
	SourceField      string `json:"sourceField"`
	DestinationField string `json:"destinationField"`
	IDField          string `json:"idField"`
}

type graphistryEdges struct {
	Source      string `json:"src"`
	Destination string `json:"dst"`
	Title       string `json:"edgeTitle"`
}

type graphistryNodes struct {
	NodeID string `json:"node"`
	Label  string `json:"pointLabel"`
	Title  string `json:"pointTitle"`
	Color  int    `json:"pointColor"`
	Type   string `json:"type"`
	Source string `json:"source"`
}

type graphistryREST struct {
	Name     string             `json:"name"`
	Type     string             `json:"type"`
	Bindings graphistryBindings `json:"bindings"`
	Edges    []graphistryEdges  `json:"graph"`
	Nodes    []graphistryNodes  `json:"labels"`
}

// WriteGraphistryData generates a JSON file to display the Amass graph using Graphistry.
func WriteGraphistryData(output io.Writer, nodes []Node, edges []Edge) {
	colors := map[string]int{
		"Subdomain": 3,
		"Domain":    5,
		"IPAddress": 7,
		"PTR":       10,
		"NS":        0,
		"MX":        9,
		"Netblock":  4,
		"AS":        1,
	}
	name := "Amass_" + time.Now().Format("Jan_2_2006_15_04_05")
	restJSON := &graphistryREST{
		Name: name,
		Type: "edgelist",
		Bindings: graphistryBindings{
			SourceField:      "src",
			DestinationField: "dst",
			IDField:          "node",
		},
	}

	for idx, node := range nodes {
		restJSON.Nodes = append(restJSON.Nodes, graphistryNodes{
			NodeID: strconv.Itoa(idx),
			Label:  node.Label,
			Title:  node.Title,
			Color:  colors[node.Type],
			Type:   node.Type,
			Source: node.Source,
		})
	}

	for _, edge := range edges {
		restJSON.Edges = append(restJSON.Edges, graphistryEdges{
			Source:      strconv.Itoa(edge.From),
			Destination: strconv.Itoa(edge.To),
			Title:       edge.Title,
		})
	}

	enc := json.NewEncoder(output)
	enc.SetIndent("", "  ")
	enc.Encode(restJSON)
}
