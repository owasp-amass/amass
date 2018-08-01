// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

type Robtex struct {
	BaseDataSource
}

func NewRobtex() DataSource {
	r := new(Robtex)

	r.BaseDataSource = *NewBaseDataSource(API, "Robtex")
	return r
}

type robtexJSON struct {
	Name string `json:"rrname"`
	Data string `json:"rrdata"`
	Type string `json:"rrtype"`
}

func (r *Robtex) Query(domain, sub string) []string {
	var ips []string
	var unique []string

	if domain != sub {
		return unique
	}

	url := "https://freeapi.robtex.com/pdns/forward/" + domain
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		r.log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

	for _, line := range r.parseJSON(page) {
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
			r.log(fmt.Sprintf("%s: %v", url, err))
			continue
		}

		for _, line := range r.parseJSON(pdns) {
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

func (r *Robtex) parseJSON(page string) []robtexJSON {
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
