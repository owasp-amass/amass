// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
)

type gigablast struct {
	domain     string
	quantity   int
	limit      int
	subdomains chan string
}

func (g gigablast) String() string {
	return "Gigablast Search"
}

func (g gigablast) Domain() string {
	return g.domain
}

func (g gigablast) Quantity() int {
	return g.quantity
}

func (g gigablast) Limit() int {
	return g.limit
}

func (g gigablast) URLByPageNum(page int) string {
	s := strconv.Itoa(g.quantity * page)

	u, _ := url.Parse("http://www.gigablast.com/search")
	u.RawQuery = url.Values{"q": {g.domain}, "niceness": {"1"},
		"icc": {"1"}, "dr": {"1"}, "spell": {"0"}, "s": {s}}.Encode()

	return u.String()
}

func (g *gigablast) Search(done chan int) {
	done <- SearchQuery(g, g.subdomains)
	return
}

func GigablastSearch(domain string, subdomains chan string) Searcher {
	g := new(gigablast)

	g.domain = domain
	g.subdomains = subdomains
	// Gigablast.com appears to be hardcoded at 10 results per page
	g.quantity = 10
	g.limit = 200
	return g
}
