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
	XMLNS    string = "http://www.gephi.org/gexf"
	XMLNSVIZ string = "http://www.gephi.org/gexf/viz"

	ClassNode string = "node"
	ClassEdge string = "edge"

	ModeStatic  string = "static"
	ModeDynamic string = "dynamic"

	EdgeTypeDirected   string = "directed"
	EdgeTypeUndirected string = "undirected"
	EdgeTypeMutual     string = "mutual"
)

type gephiAttrValue struct {
	For   string `xml:"for,attr"`
	Value string `xml:"value,attr"`
}

type gephiAttribute struct {
	ID      string `xml:"id,attr"`
	Title   string `xml:"title,attr"`
	Type    string `xml:"type,attr"`
	Default string `xml:"default,omitempty"`
}

type gephiAttributes struct {
	Class string           `xml:"class,attr"`
	Attrs []gephiAttribute `xml:"attribute"`
}

type gephiParent struct {
	For string `xml:"for,attr"`
}

type gephiColor struct {
	R uint8 `xml:"r,attr"`
	G uint8 `xml:"g,attr"`
	B uint8 `xml:"b,attr"`
}

type gephiNode struct {
	ID      string           `xml:"id,attr"`
	Label   string           `xml:"label,attr,omitempty"`
	Attrs   []gephiAttrValue `xml:"attvalues>attvalue,omitempty"`
	Parents []gephiParent    `xml:"parents>parent"`
	Color   *gephiColor      `xml:"viz:color,omitempty"`
}

type gephiEdge struct {
	ID     string           `xml:"id,attr"`
	Label  string           `xml:"label,attr,omitempty"`
	Type   string           `xml:"type,attr,omitempty"`
	Source string           `xml:"source,attr"`
	Target string           `xml:"target,attr"`
	Weight float64          `xml:"weight,attr,omitempty"`
	Attrs  []gephiAttrValue `xml:"attvalues>attvalue,omitempty"`
}

type gephiMeta struct {
	LastModified string `xml:"lastmodifieddate,attr"`
	Creator      string `xml:"creator"`
	Keywords     string `xml:"keywords,omitempty"`
	Desc         string `xml:"description"`
}

type gephiGraph struct {
	Mode     string          `xml:"mode,attr,omitempty"`
	EdgeType string          `xml:"defaultedgetype,attr,omitempty"`
	Attrs    gephiAttributes `xml:"attributes,omitempty"`
	Nodes    []gephiNode     `xml:"nodes>node,omitempty"`
	Edges    []gephiEdge     `xml:"edges>edge,omitempty"`
}

type gexf struct {
	XMLName xml.Name
	Version string     `xml:"version,attr"`
	Viz     string     `xml:"xmlns:viz,attr"`
	Meta    gephiMeta  `xml:"meta"`
	Graph   gephiGraph `xml:"graph"`
}

var (
	gephiGreen  = &gephiColor{R: 34, G: 153, B: 84}
	gephiRed    = &gephiColor{R: 242, G: 44, B: 13}
	gephiOrange = &gephiColor{R: 243, G: 156, B: 18}
	gephiYellow = &gephiColor{R: 237, G: 243, B: 26}
	gephiCyan   = &gephiColor{R: 26, G: 243, B: 240}
	gephiPurple = &gephiColor{R: 142, G: 68, B: 173}
	gephiPink   = &gephiColor{R: 243, G: 26, B: 188}
	gephiBlue   = &gephiColor{R: 26, G: 69, B: 243}
)

func WriteGephiData(nodes []Node, edges []Edge, output io.Writer) {
	bufwr := bufio.NewWriter(output)

	bufwr.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	bufwr.Flush()

	doc := &gexf{
		XMLName: xml.Name{
			Space: XMLNS,
			Local: "gexf",
		},
		Version: "1.3",
		Viz:     XMLNSVIZ,
		Meta: gephiMeta{
			LastModified: time.Now().UTC().Format("2006-01-02"),
			Creator:      "Amass - https://github.com/caffix/amass",
			Desc:         "Internet Satellite Imagery",
		},
		Graph: gephiGraph{
			Mode:     ModeStatic,
			EdgeType: EdgeTypeDirected,
			Attrs: gephiAttributes{
				Class: ClassNode,
				Attrs: []gephiAttribute{
					{ID: "0", Title: "Title", Type: "string"},
					{ID: "1", Title: "Source", Type: "string"},
					{ID: "2", Title: "Type", Type: "string"},
				},
			},
		},
	}

	for idx, n := range nodes {
		var color *gephiColor

		switch n.Type {
		case "Subdomain":
			color = gephiGreen
		case "Domain":
			color = gephiRed
		case "IPAddress":
			color = gephiOrange
		case "PTR":
			color = gephiYellow
		case "NS":
			color = gephiCyan
		case "MX":
			color = gephiPurple
		case "Netblock":
			color = gephiPink
		case "AS":
			color = gephiBlue
		}

		doc.Graph.Nodes = append(doc.Graph.Nodes, gephiNode{
			ID:    strconv.Itoa(idx),
			Label: n.Label,
			Attrs: []gephiAttrValue{
				{For: "0", Value: n.Title},
				{For: "1", Value: n.Source},
				{For: "2", Value: n.Type},
			},
			Color: color,
		})
	}

	for idx, e := range edges {
		doc.Graph.Edges = append(doc.Graph.Edges, gephiEdge{
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
