// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
)

type censys struct {
	domain     string
	subdomains chan *Subdomain
}

func (c censys) String() string {
	return "Censys Search"
}

func (c censys) Domain() string {
	return c.domain
}

func (c censys) Quantity() int {
	return 1
}

func (c censys) Limit() int {
	return 1
}

func (c censys) URLByPageNum(page int) string {
	format := "https://www.censys.io/domain/%s/table"

	return fmt.Sprintf(format, c.domain)
}

func (c *censys) Search(done chan int) {
	done <- SearchQuery(c, c.subdomains)
	return
}

func CensysSearch(domain string, subdomains chan *Subdomain) Searcher {
	c := new(censys)

	c.domain = domain
	c.subdomains = subdomains
	return c
}
