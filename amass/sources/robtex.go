// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"log"
	"strings"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	RobtexSourceString string = "Robtex"
)

type robtexJSON struct {
	Name string `json:"rrname"`
	Data string `json:"rrdata"`
	Type string `json:"rrtype"`
}

func RobtexQuery(domain, sub string, log *log.Logger) []string {
	var ips []string
	var unique []string

	if domain != sub {
		return unique
	}

	url := "https://freeapi.robtex.com/pdns/forward/" + domain
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		log.Printf("Robtex error: %s: %v", url, err)
		return unique
	}

	lines := robtexParseJSON(page)
	for _, line := range lines {
		if line.Type == "A" {
			ips = utils.UniqueAppend(ips, line.Data)
		}
	}

	var list string
	for _, ip := range ips {
		time.Sleep(500 * time.Millisecond)

		url = "https://freeapi.robtex.com/pdns/reverse/" + ip
		pdns, err := utils.GetWebPage(url, nil)
		if err != nil {
			log.Printf("Robtex error: %s: %v", url, err)
			continue
		}

		rev := robtexParseJSON(pdns)
		for _, line := range rev {
			list += line.Name + " "
		}
	}

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(list, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func robtexParseJSON(page string) []robtexJSON {
	var lines []robtexJSON

	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j robtexJSON

		err := json.Unmarshal([]byte(line), &j)
		if err != nil {
			continue
		}

		lines = append(lines, j)
	}
	return lines
}
