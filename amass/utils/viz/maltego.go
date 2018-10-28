// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/OWASP/Amass/amass/utils"
)

// WriteMaltegoData converts the Amass graph nodes and edges into a
// structured table format (CSV) that can be input by Maltego.
func WriteMaltegoData(output io.Writer, nodes []Node, edges []Edge) {
	filter := make(map[int]struct{})
	types := []string{
		"maltego.Domain",
		"maltego.DNSName",
		"maltego.NSRecord",
		"maltego.MXRecord",
		"maltego.IPv4Address",
		"maltego.Netblock",
		"maltego.AS",
		"maltego.Company",
		"maltego.DNSName",
	}
	// Print the column types in the first row
	fmt.Fprintln(output, strings.Join(types, ","))
	// Start the graph tranersal from the autonomous systems
	for idx, node := range nodes {
		if node.Type == "AS" {
			traverseTree(output, idx, nodes, edges, filter)
		}
	}
}

func checkFilter(id int, filter map[int]struct{}) bool {
	if _, ok := filter[id]; ok {
		return true
	}
	filter[id] = struct{}{}
	return false
}

func typeToIndex(t string) int {
	var idx int

	switch t {
	case "Domain":
		idx = 0
	case "Subdomain":
		idx = 1
	case "PTR":
		idx = 8
	case "CNAME":
		idx = 8
	case "IPAddress":
		idx = 4
	case "NS":
		idx = 2
	case "MX":
		idx = 3
	case "Netblock":
		idx = 5
	case "AS":
		idx = 6
	case "Company":
		idx = 7
	}
	return idx
}

func writeMaltegoTableLine(out io.Writer, data1, type1, data2, type2 string) {
	row := []string{"", "", "", "", "", "", "", "", ""}

	idx1 := typeToIndex(type1)
	row[idx1] = data1
	if type1 == "Netblock" {
		row[idx1] = cidrToMaltegoNetblock(data1)
	}
	idx2 := typeToIndex(type2)
	row[idx2] = data2
	if type2 == "Netblock" {
		row[idx2] = cidrToMaltegoNetblock(data2)
	}
	fmt.Fprintln(out, strings.Join(row, ","))
}

func traverseTree(out io.Writer, id int, nodes []Node, edges []Edge, filter map[int]struct{}) {
	d1 := nodes[id].Label
	t1 := nodes[id].Type

	var from bool
	if t1 == "Netblock" || t1 == "AS" {
		from = true
	}

	if checkFilter(id, filter) {
		return
	}

	// Print the line containing the AS company
	if t1 == "AS" {
		parts := strings.Split(nodes[id].Title, ":")
		company := strings.Replace(strings.TrimSpace(parts[2]), ",", "", -1)
		writeMaltegoTableLine(out, d1, t1, company, "Company")
	}

	for _, edge := range edges {
		subFrom := from
		n, found := selectNextEdge(id, from, edge)
		if !found && (t1 == "Subdomain" || t1 == "Domain") {
			subFrom = true
			n, found = selectNextEdge(id, subFrom, edge)
		}
		if !found {
			continue
		}
		d2 := nodes[n].Label
		t2 := nodes[n].Type
		// Need to properly handle CNAME records
		if strings.Contains(edge.Title, "CNAME") {
			if subFrom {
				writeMaltegoTableLine(out, d1, "CNAME", d2, t2)
			} else {
				writeMaltegoTableLine(out, d1, t1, d2, "CNAME")
			}
		} else {
			writeMaltegoTableLine(out, d1, t1, d2, t2)
		}
		traverseTree(out, n, nodes, edges, filter)
	}
}

func selectNextEdge(id int, from bool, edge Edge) (int, bool) {
	if from {
		if edge.From == id {
			return edge.To, true
		}
	} else {
		if edge.To == id {
			return edge.From, true
		}
	}
	return 0, false
}

func cidrToMaltegoNetblock(cidr string) string {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return ""
	}
	ip1, ip2 := utils.NetFirstLast(ipnet)
	return ip1.String() + "-" + ip2.String()
}
