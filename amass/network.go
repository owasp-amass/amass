// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"sort"
	"strings"
	"bufio"
	"strconv"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// LookupASNsByName returns core.ASNRequest objects for autonomous systems with
// descriptions that contain the string provided by the parameter.
func LookupASNsByName(s string) ([]*core.ASNRequest, error) {
	var records []*core.ASNRequest

	s = strings.ToLower(s)
	url := "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/asnlist.txt"
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		return records, err
	}

	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err == nil {
			parts := strings.Split(strings.TrimSpace(line), ",")

			if strings.Contains(strings.ToLower(parts[1]), s) {
				a, err := strconv.Atoi(parts[0])
				if err == nil {
					records = append(records, &core.ASNRequest{
						ASN: a,
						Description: parts[1],
					})
				}
			}
		}
	}
	return records, nil
}

// ReverseWhois returns domain names that are related to the domain provided
func ReverseWhois(domain string) ([]string, error) {
	var domains []string

	
	sort.Strings(domains)
	return domains, nil
}
