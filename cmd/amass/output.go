// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/core"
	"github.com/fatih/color"
)

type OutputParams struct {
	Enum     *amass.Enumeration
	Verbose  bool
	PrintIPs bool
	FileOut  string
	JSONOut  string
}

type ASNData struct {
	Name      string
	Netblocks map[string]int
}

type JsonAddr struct {
	IP          string `json:"ip"`
	CIDR        string `json:"cidr"`
	ASN         int    `json:"asn"`
	Description string `json:"desc"`
}

type JsonSave struct {
	Name      string     `json:"name"`
	Domain    string     `json:"domain"`
	Addresses []JsonAddr `json:"addresses"`
	Tag       string     `json:"tag"`
	Source    string     `json:"source"`
}

func WriteJSONData(f *os.File, result *core.AmassOutput) {
	save := &JsonSave{
		Name:   result.Name,
		Domain: result.Domain,
		Tag:    result.Tag,
		Source: result.Source,
	}

	for _, addr := range result.Addresses {
		save.Addresses = append(save.Addresses, JsonAddr{
			IP:          addr.Address.String(),
			CIDR:        addr.Netblock.String(),
			ASN:         addr.ASN,
			Description: addr.Description,
		})
	}

	enc := json.NewEncoder(f)
	enc.Encode(save)
}

func ListDomains(enum *amass.Enumeration, outfile string) {
	var fileptr *os.File
	var bufwr *bufio.Writer

	if outfile != "" {
		fileptr, err := os.OpenFile(outfile, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			bufwr = bufio.NewWriter(fileptr)
			defer fileptr.Close()
		}
	}

	for _, d := range enum.Domains() {
		g.Println(d)

		if bufwr != nil {
			bufwr.WriteString(d + "\n")
			bufwr.Flush()
		}
	}

	if bufwr != nil {
		fileptr.Sync()
	}
}

func PrintBanner() {
	rightmost := 76
	desc := "In-Depth DNS Enumeration"
	author := "Authored By " + amass.Author

	pad := func(num int) {
		for i := 0; i < num; i++ {
			fmt.Print(" ")
		}
	}
	r.Println(amass.Banner)
	pad(rightmost - len(amass.Version))
	y.Println(amass.Version)
	pad(rightmost - len(desc))
	y.Println(desc)
	pad(rightmost - len(author))
	y.Printf("%s\n\n\n", author)
}

func WriteTextData(f *os.File, source, name, comma, ips string) {
	fmt.Fprintf(f, "%s%s%s%s\n", source, name, comma, ips)
}

func ResultToLine(result *core.AmassOutput, params *OutputParams) (string, string, string, string) {
	var source, comma, ips string

	if params.Verbose {
		source = fmt.Sprintf("%-18s", "["+result.Source+"] ")
	}
	if params.PrintIPs {
		comma = ","

		for i, a := range result.Addresses {
			if i != 0 {
				ips += ","
			}
			ips += a.Address.String()
		}
	}
	return source, result.Name, comma, ips
}

func ManageOutput(params *OutputParams) {
	var total int
	var err error
	var outptr, jsonptr *os.File

	if params.FileOut != "" {
		outptr, err = os.OpenFile(params.FileOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			defer func() {
				outptr.Sync()
				outptr.Close()
			}()
		}
	}

	if params.JSONOut != "" {
		jsonptr, err = os.OpenFile(params.JSONOut, os.O_WRONLY|os.O_CREATE, 0644)
		if err == nil {
			defer func() {
				jsonptr.Sync()
				jsonptr.Close()
			}()
		}
	}

	tags := make(map[string]int)
	asns := make(map[int]*ASNData)
	// Collect all the names returned by the enumeration
	for result := range params.Enum.Output {
		total++
		UpdateData(result, tags, asns)

		source, name, comma, ips := ResultToLine(result, params)
		fmt.Fprintf(color.Output, "%s%s%s%s\n",
			blue(source), green(name), green(comma), yellow(ips))
		// Handle writing the line to a specified output file
		if outptr != nil {
			WriteTextData(outptr, source, name, comma, ips)
		}
		// Handle encoding the result as JSON
		if jsonptr != nil {
			WriteJSONData(jsonptr, result)
		}
	}
	// Check to print the summary information
	if params.Verbose {
		PrintSummary(total, tags, asns)
	}
	close(Finished)
}

func UpdateData(output *core.AmassOutput, tags map[string]int, asns map[int]*ASNData) {
	tags[output.Tag]++

	// Update the ASN information
	for _, addr := range output.Addresses {
		data, found := asns[addr.ASN]
		if !found {
			asns[addr.ASN] = &ASNData{
				Name:      addr.Description,
				Netblocks: make(map[string]int),
			}
			data = asns[addr.ASN]
		}
		// Increment how many IPs were in this netblock
		data.Netblocks[addr.Netblock.String()]++
	}
}

func PrintSummary(total int, tags map[string]int, asns map[int]*ASNData) {
	if total == 0 {
		r.Println("No names were discovered")
		return
	}
	pad := func(num int, chr string) {
		for i := 0; i < num; i++ {
			b.Print(chr)
		}
	}

	fmt.Println()
	// Print the header information
	title := "OWASP Amass v"
	b.Print(title + amass.Version)
	num := 80 - (len(title) + len(amass.Version) + len(amass.Author))
	pad(num, " ")
	b.Printf("%s\n", amass.Author)
	pad(8, "----------")
	fmt.Fprintf(color.Output, "\n%s%s", yellow(strconv.Itoa(total)), green(" names discovered - "))
	// Print the stats using tag information
	num, length := 1, len(tags)
	for k, v := range tags {
		fmt.Fprintf(color.Output, "%s: %s", green(k), yellow(strconv.Itoa(v)))
		if num < length {
			g.Print(", ")
		}
		num++
	}
	fmt.Println()

	if len(asns) == 0 {
		return
	}
	// Another line gets printed
	pad(8, "----------")
	fmt.Println()
	// Print the ASN and netblock information
	for asn, data := range asns {
		fmt.Fprintf(color.Output, "%s%s %s %s\n",
			blue("ASN: "), yellow(strconv.Itoa(asn)), green("-"), green(data.Name))

		for cidr, ips := range data.Netblocks {
			countstr := fmt.Sprintf("\t%-4s", strconv.Itoa(ips))
			cidrstr := fmt.Sprintf("\t%-18s", cidr)

			fmt.Fprintf(color.Output, "%s%s %s\n",
				yellow(cidrstr), yellow(countstr), blue("Subdomain Name(s)"))
		}
	}
}
