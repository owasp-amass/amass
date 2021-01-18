// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"bufio"
	"compress/gzip"
	"encoding/csv"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
)

// LookupASNsByName returns requests.ASNRequest objects for autonomous systems with
// descriptions that contain the string provided by the parameter.
func LookupASNsByName(s string) ([]int, []string, error) {
	var asns []int
	var descs []string

	fsOnce.Do(openTheFS)

	content, err := StatikFS.Open("/asnlist.txt")
	if err != nil {
		return asns, descs, fmt.Errorf("Failed to obtain the embedded ASN information: asnlist.txt: %v", err)
	}
	defer content.Close()

	s = strings.ToLower(s)
	scanner := bufio.NewScanner(content)
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err == nil {
			parts := strings.Split(strings.TrimSpace(line), ",")

			if strings.Contains(strings.ToLower(parts[1]), s) {
				a, err := strconv.Atoi(parts[0])
				if err == nil {
					asns = append(asns, a)
					descs = append(descs, parts[1])
				}
			}
		}
	}

	return asns, descs, nil
}

// IP2ASN is a range record provided by the iptoasn.com service.
type IP2ASN struct {
	FirstIP     net.IP
	LastIP      net.IP
	ASN         int
	CC          string
	Description string
}

// GetIP2ASNData returns all the range records read from the 'ip2asn-combined.tsv.gz' file provided by the iptoasn.com service.
func GetIP2ASNData() ([]*IP2ASN, error) {
	fsOnce.Do(openTheFS)

	file, err := StatikFS.Open("/ip2asn-combined.tsv.gz")
	if err != nil {
		return nil, fmt.Errorf("Failed to open the 'ip2asn-combined.tsv.gz' file: %v", err)
	}
	defer file.Close()

	zr, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("Failed to obtain the gzip reader for the 'ip2asn-combined.tsv.gz' file: %v", err)
	}
	defer zr.Close()

	var ranges []*IP2ASN
	r := csv.NewReader(zr)
	r.Comma = '\t'
	r.FieldsPerRecord = 5
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		if asn, err := strconv.Atoi(record[2]); err == nil {
			ranges = append(ranges, &IP2ASN{
				FirstIP:     net.ParseIP(record[0]),
				LastIP:      net.ParseIP(record[1]),
				ASN:         asn,
				CC:          record[3],
				Description: record[4],
			})
		}
	}

	return ranges, nil
}
