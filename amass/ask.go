// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
)

type ask struct {
	domain     string
	quantity   int
	limit      int
	subdomains chan string
}

func (a ask) String() string {
	return "Ask Search"
}

func (a ask) Domain() string {
	return a.domain
}

func (a ask) Quantity() int {
	return a.quantity
}

func (a ask) Limit() int {
	return a.limit
}

func (a ask) URLByPageNum(page int) string {
	pu := strconv.Itoa(a.quantity)
	p := strconv.Itoa(page)

	u, _ := url.Parse("http://www.ask.com/web")
	u.RawQuery = url.Values{"q": {a.domain}, "pu": {pu}, "page": {p}}.Encode()

	return u.String()
}

func (a *ask) Search(done chan int) {
	done <- SearchQuery(a, a.subdomains)
	return
}

func AskSearch(domain string, subdomains chan string) Searcher {
	a := new(ask)

	a.domain = domain
	// ask.com appears to be hardcoded at 10 results per page
	a.quantity = 10
	a.limit = 200
	a.subdomains = subdomains
	return a
}
