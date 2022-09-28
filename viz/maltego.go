// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package viz

import (
	"archive/zip"
	"fmt"
	"io"
	"net"
	"os"
	"strings"

	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/resources"
)

// WriteMaltegoData converts the Amass graph nodes and edges into a
// structured table format (CSV) that can be imported by Maltego.
func WriteMaltegoData(output io.Writer, nodes []Node, edges []Edge) {
	filter := make(map[int]struct{})
	types := []string{
		"maltego.Domain",
		"maltego.DNSName",
		"maltego.NSRecord",
		"maltego.MXRecord",
		"maltego.IPv4Address",
		"maltego.IPv6Address",
		"maltego.Netblock",
		"maltego.AS",
		"maltego.Company",
		"maltego.DNSName",
	}
	// Print the column types in the first row
	fmt.Fprintln(output, strings.Join(types, ","))
	// Start the graph traversal from the autonomous systems
	for idx, node := range nodes {
		if node.Type == "as" {
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
	case "domain":
		idx = 0
	case "subdomain":
		idx = 1
	case "ptr":
		idx = 9
	case "cname":
		idx = 8
	case "v4address":
		idx = 4
	case "v6address":
		idx = 5
	case "ns":
		idx = 2
	case "mx":
		idx = 3
	case "netblock":
		idx = 6
	case "as":
		idx = 7
	case "company":
		idx = 8
	}
	return idx
}

func writeMaltegoTableLine(out io.Writer, data1, type1, data2, type2 string) {
	row := []string{"", "", "", "", "", "", "", "", "", ""}

	idx1 := typeToIndex(type1)
	row[idx1] = data1
	if type1 == "netblock" {
		row[idx1] = cidrToMaltegoNetblock(data1)
	}
	idx2 := typeToIndex(type2)
	row[idx2] = data2
	if type2 == "netblock" {
		row[idx2] = cidrToMaltegoNetblock(data2)
	}
	fmt.Fprintln(out, strings.Join(row, ","))
}

func traverseTree(out io.Writer, id int, nodes []Node, edges []Edge, filter map[int]struct{}) {
	d1 := nodes[id].Label
	t1 := nodes[id].Type

	if "address" == t1 {
		t1 = getIpVersion(d1) // get exact address version
	}

	var from bool
	if t1 == "netblock" || t1 == "as" {
		from = true
	}

	if checkFilter(id, filter) {
		return
	}
	// Print the line containing the AS company
	if t1 == "as" {
		parts := strings.Split(nodes[id].Title, ":")
		company := strings.Replace(strings.TrimSpace(parts[2]), ",", "", -1)
		writeMaltegoTableLine(out, d1, t1, company, "company")
	}

	for _, edge := range edges {
		subFrom := from
		n, found := selectNextEdge(id, from, edge)
		if !found && (t1 == "subdomain" || t1 == "domain") {
			subFrom = true
			n, found = selectNextEdge(id, subFrom, edge)
		}
		if !found {
			continue
		}
		d2 := nodes[n].Label
		t2 := nodes[n].Type
		if "address" == t2 {
			t2 = getIpVersion(d2) // get exact address version
		}
		// Need to properly handle CNAME records
		if strings.Contains(edge.Title, "cname") {
			if subFrom {
				writeMaltegoTableLine(out, d1, "cname", d2, t2)
			} else {
				writeMaltegoTableLine(out, d1, t1, d2, "cname")
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

	ip1, ip2 := amassnet.FirstLast(ipnet)
	return ip1.String() + "-" + ip2.String()
}

// This function returns the IP address version number that should be used to set exact Maltego
// IP Address Entity type
func getIpVersion(address string) string {
	if strings.Contains(address, ":") { // IPv6 address
		return "v6address"
	}
	return "v4address" // all others are considered IPv4 address
}

// CreateMaltegoConfig function creates a default mapping configuration for Maltego that can be used
// to import the Maltego csv
func CreateMaltegoConfig(mtzConfigPath string) error {
	if _, err := os.Stat(mtzConfigPath); err == nil { // mtz config already exists
		return nil
	}
	file, err := resources.GetResourceFile("maltego_mapping_config.tmapping")
	if nil != err {
		return err
	}
	// *.mtz file is just a zip archive
	mtz, err := os.Create(mtzConfigPath)
	if nil != err {
		return err
	}
	defer mtz.Close()
	archiveWriter := zip.NewWriter(mtz)
	defer archiveWriter.Close()
	mtzWriter, err := archiveWriter.Create("TabularMappings/Amass Graph Data Mapping.tmapping")
	if nil != err {
		return err
	}
	io.Copy(mtzWriter, file)
	return nil
}
