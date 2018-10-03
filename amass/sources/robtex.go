// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

type Robtex struct {
	BaseDataSource
}

func NewRobtex(srv core.AmassService) DataSource {
	r := new(Robtex)

	r.BaseDataSource = *NewBaseDataSource(srv, core.API, "Robtex")
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
		r.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	r.Service.SetActive()

	for _, line := range r.parseJSON(page) {
		if line.Type == "A" {
			ips = utils.UniqueAppend(ips, line.Data)
		}
	}

	var list string
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
loop:
	for _, ip := range ips {
		r.Service.SetActive()

		select {
		case <-r.Service.Quit():
			break loop
		case <-t.C:
			url = "https://freeapi.robtex.com/pdns/reverse/" + ip
			pdns, err := utils.GetWebPage(url, nil)
			if err != nil {
				r.Service.Config().Log.Printf("%s: %v", url, err)
				continue
			}

			for _, line := range r.parseJSON(pdns) {
				list += line.Name + " "
			}
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
