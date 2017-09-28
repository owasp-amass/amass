// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type robtex struct {
	domain     string
	subdomains chan string
}

func (r robtex) String() string {
	return "Robtex Search"
}

func (r robtex) Domain() string {
	return r.domain
}

func (r robtex) Quantity() int {
	return 1
}

func (r robtex) Limit() int {
	return 1
}

func (r robtex) URLByPageNum(page int) string {
	format := "https://www.robtex.com/dns-lookup/%s"

	return fmt.Sprintf(format, r.domain)
}

func (r *robtex) Search(done chan int) {
	done <- SearchQuery(r, r.subdomains)
	return
}

func RobtexSearch(domain string, subdomains chan string) Searcher {
	r := new(robtex)

	r.domain = domain
	r.subdomains = subdomains
	return r
}

type RobtexDNSResolve struct {
	Name      string `json:"rrname"`
	Data      string `json:"rrdata"`
	Type      string `json:"rrtype"`
	TimeFirst int    `json:"time_first"`
	TimeLast  int    `json:"time_last"`
	Count     int    `json:"count"`
}

type robtexDNS struct {
	Valid chan *ValidSubdomain
	next  chan string
}

func (rd *robtexDNS) processSubdomains() {
	// do not use this service more than once per second
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()

	for range t.C {
		sd := <-rd.next

		page := GetWebPage("https://freeapi.robtex.com/pdns/forward/" + sd)
		if page == "" {
			continue
		}

		// each line is a separate json object
		objs := strings.Split(page, "\n")
		for _, j := range objs {
			var msg RobtexDNSResolve

			err := json.Unmarshal([]byte(j), &msg)
			if err != nil {
				continue
			}

			if msg.Type == "A" || msg.Type == "AAAA" {
				rd.Valid <- &ValidSubdomain{sd, msg.Data}
				break
			}
		}
	}
	return
}

func (rd *robtexDNS) CheckSubdomain(subdomain string) {
	rd.next <- subdomain
}

func (rd *robtexDNS) CheckSubdomains(subdomains []string) {
	for _, s := range subdomains {
		rd.next <- s
	}
}

func RobtexDNS(valid chan *ValidSubdomain) DNSChecker {
	rd := new(robtexDNS)

	rd.Valid = valid
	rd.next = make(chan string, 40)

	go rd.processSubdomains()
	return rd
}
