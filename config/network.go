// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"bufio"
	"fmt"
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
