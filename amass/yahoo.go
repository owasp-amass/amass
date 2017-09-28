// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
)

type yahoo struct {
	domain     string
	quantity   int
	limit      int
	subdomains chan string
}

func (y yahoo) String() string {
	return "Yahoo Search"
}

func (y yahoo) Domain() string {
	return y.domain
}

func (y yahoo) Quantity() int {
	return y.quantity
}

func (y yahoo) Limit() int {
	return y.limit
}

func (y yahoo) URLByPageNum(page int) string {
	b := strconv.Itoa(y.quantity * page)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("http://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"\"" + y.domain + "\""}, "b": {b}, "pz": {pz}}.Encode()

	return u.String()
}

func (y *yahoo) Search(done chan int) {
	done <- SearchQuery(y, y.subdomains)
	return
}

func YahooSearch(domain string, subdomains chan string) Searcher {
	y := new(yahoo)

	y.domain = domain
	y.quantity = 20
	y.limit = 400
	y.subdomains = subdomains
	return y
}
