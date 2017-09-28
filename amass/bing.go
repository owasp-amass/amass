// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
)

type bing struct {
	domain     string
	quantity   int
	limit      int
	subdomains chan string
}

func (b bing) String() string {
	return "Bing Search"
}

func (b bing) Domain() string {
	return b.domain
}

func (b bing) Quantity() int {
	return b.quantity
}

func (b bing) Limit() int {
	return b.limit
}

func (b bing) URLByPageNum(page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)

	u, _ := url.Parse("http://www.bing.com/search")
	u.RawQuery = url.Values{"q": {"domain:" + b.domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()

	return u.String()
}

func (b *bing) Search(done chan int) {
	done <- SearchQuery(b, b.subdomains)
	return
}

func BingSearch(domain string, subdomains chan string) Searcher {
	b := new(bing)

	b.domain = domain
	b.quantity = 20
	b.limit = 400
	b.subdomains = subdomains
	return b
}
