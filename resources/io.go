// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"compress/gzip"
	"embed"
	"encoding/csv"
	"fmt"
	"io"
	"io/fs"
	"net"
	"path/filepath"
	"strconv"
)

//go:embed scripts ip2asn-combined.tsv.gz alterations.txt namelist.txt user_agents.txt
var resourceFS embed.FS

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
	file, err := resourceFS.Open("ip2asn-combined.tsv.gz")
	if err != nil {
		return nil, fmt.Errorf("failed to open the 'ip2asn-combined.tsv.gz' file: %v", err)
	}
	defer file.Close()

	zr, err := gzip.NewReader(file)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain the gzip reader for the 'ip2asn-combined.tsv.gz' file: %v", err)
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

func GetDefaultScripts() ([]string, error) {
	var scripts []string

	ferr := fs.WalkDir(resourceFS, "scripts", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Is this file not a script?
		if d.IsDir() || filepath.Ext(d.Name()) != ".ads" {
			return nil
		}
		// Get the script content
		data, err := resourceFS.ReadFile(path)
		if err != nil {
			return err
		}

		scripts = append(scripts, string(data))
		return nil
	})

	return scripts, ferr
}

func GetResourceFile(path string) (io.Reader, error) {
	file, err := resourceFS.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to obtain the embedded file: %s: %v", path, err)
	}
	return file, err
}
