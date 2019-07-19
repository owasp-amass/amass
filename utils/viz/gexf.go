// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
	"bufio"
	"encoding/xml"
	"io"
	"strconv"
	"time"
)

const (
	xmlNS    string = "http://www.gephi.org/gexf"
	xmlNSVIZ string = "http://www.gephi.org/gexf/viz"

	classNode string = "node"
	classEdge string = "edge"

	modeStatic  string = "static"
	modeDynamic string = "dynamic"

	edgeTypeDirected   string = "directed"
	edgeTypeUndirected string = "undirected"
	edgeTypeMutual     string = "mutual"
)

type gexfAttrValue struct {
	For   string `xml:"for,attr"`
	Value string `xml:"value,attr"`
}

type gexfAttribute struct {
	ID      string `xml:"id,attr"`
	Title   string `xml:"title,attr"`
	Type    string `xml:"type,attr"`
	Default string `xml:"default,omitempty"`
}

type gexfAttributes struct {
	Class string          `xml:"class,attr"`
	Attrs []gexfAttribute `xml:"attribute"`
}

type gexfParent struct {
	For string `xml:"for,attr"`
}

type gexfColor struct {
	R uint8 `xml:"r,attr"`
	G uint8 `xml:"g,attr"`
	B uint8 `xml:"b,attr"`
}

type gexfNode struct {
	ID      string          `xml:"id,attr"`
	Label   string          `xml:"label,attr,omitempty"`
	Attrs   []gexfAttrValue `xml:"attvalues>attvalue,omitempty"`
	Parents []gexfParent    `xml:"parents>parent"`
	Color   *gexfColor      `xml:"viz:color,omitempty"`
}

type gexfEdge struct {
	ID     string          `xml:"id,attr"`
	Label  string          `xml:"label,attr,omitempty"`
	Type   string          `xml:"type,attr,omitempty"`
	Source string          `xml:"source,attr"`
	Target string          `xml:"target,attr"`
	Weight float64         `xml:"weight,attr,omitempty"`
	Attrs  []gexfAttrValue `xml:"attvalues>attvalue,omitempty"`
}

type gexfMeta struct {
	LastModified string `xml:"lastmodifieddate,attr"`
	Creator      string `xml:"creator"`
	Keywords     string `xml:"keywords,omitempty"`
	Desc         string `xml:"description"`
}

type gexfGraph struct {
	Mode     string         `xml:"mode,attr,omitempty"`
	EdgeType string         `xml:"defaultedgetype,attr,omitempty"`
	Attrs    gexfAttributes `xml:"attributes,omitempty"`
	Nodes    []gexfNode     `xml:"nodes>node,omitempty"`
	Edges    []gexfEdge     `xml:"edges>edge,omitempty"`
}

type gexf struct {
	XMLName xml.Name
	Version string    `xml:"version,attr"`
	Viz     string    `xml:"xmlns:viz,attr"`
	Meta    gexfMeta  `xml:"meta"`
	Graph   gexfGraph `xml:"graph"`
}

var (
	gexfGreen  = &gexfColor{R: 34, G: 153, B: 84}
	gexfRed    = &gexfColor{R: 242, G: 44, B: 13}
	gexfOrange = &gexfColor{R: 243, G: 156, B: 18}
	gexfYellow = &gexfColor{R: 237, G: 243, B: 26}
	gexfCyan   = &gexfColor{R: 26, G: 243, B: 240}
	gexfPurple = &gexfColor{R: 142, G: 68, B: 173}
	gexfPink   = &gexfColor{R: 243, G: 26, B: 188}
	gexfBlue   = &gexfColor{R: 26, G: 69, B: 243}
)

// WriteGEXFData generates a GEXF file to display the Amass graph using Gephi.
func WriteGEXFData(output io.Writer, nodes []Node, edges []Edge) {
	bufwr := bufio.NewWriter(output)

	bufwr.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	bufwr.Flush()

	doc := &gexf{
		XMLName: xml.Name{
			Space: xmlNS,
			Local: "gexf",
		},
		Version: "1.3",
		Viz:     xmlNSVIZ,
		Meta: gexfMeta{
			LastModified: time.Now().UTC().Format("2006-01-02"),
			Creator:      "OWASP Amass - https://github.com/OWASP/Amass",
			Desc:         "OWASP Amass Network Mapping",
		},
		Graph: gexfGraph{
			Mode:     modeStatic,
			EdgeType: edgeTypeDirected,
			Attrs: gexfAttributes{
				Class: classNode,
				Attrs: []gexfAttribute{
					{ID: "0", Title: "Title", Type: "string"},
					{ID: "1", Title: "Source", Type: "string"},
					{ID: "2", Title: "Type", Type: "string"},
				},
			},
		},
	}

	for idx, n := range nodes {
		var color *gexfColor

		switch n.Type {
		case "subdomain":
			color = gexfGreen
		case "domain":
			color = gexfRed
		case "address":
			color = gexfOrange
		case "ptr":
			color = gexfYellow
		case "ns":
			color = gexfCyan
		case "mx":
			color = gexfPurple
		case "netblock":
			color = gexfPink
		case "as":
			color = gexfBlue
		}

		doc.Graph.Nodes = append(doc.Graph.Nodes, gexfNode{
			ID:    strconv.Itoa(idx),
			Label: n.Label,
			Attrs: []gexfAttrValue{
				{For: "0", Value: n.Title},
				{For: "1", Value: n.Source},
				{For: "2", Value: n.Type},
			},
			Color: color,
		})
	}

	for idx, e := range edges {
		doc.Graph.Edges = append(doc.Graph.Edges, gexfEdge{
			ID:     strconv.Itoa(idx),
			Label:  e.Label,
			Source: strconv.Itoa(e.From),
			Target: strconv.Itoa(e.To),
		})
	}

	enc := xml.NewEncoder(bufwr)
	enc.Indent("  ", "    ")
	enc.Encode(doc)
	bufwr.Flush()
}
