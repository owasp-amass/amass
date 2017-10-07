// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
)

type robtex struct {
	domain     string
	subdomains chan *Subdomain
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

func RobtexSearch(domain string, subdomains chan *Subdomain) Searcher {
	r := new(robtex)

	r.domain = domain
	r.subdomains = subdomains
	return r
}
