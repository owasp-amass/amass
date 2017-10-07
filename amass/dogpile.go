// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
)

type dogpile struct {
	domain     string
	quantity   int
	limit      int
	subdomains chan *Subdomain
}

func (d dogpile) String() string {
	return "Dogpile Search"
}

func (d dogpile) Domain() string {
	return d.domain
}

func (d dogpile) Quantity() int {
	return d.quantity
}

func (d dogpile) Limit() int {
	return d.limit
}

func (d dogpile) URLByPageNum(page int) string {
	qsi := strconv.Itoa(d.quantity * page)

	u, _ := url.Parse("http://www.dogpile.com/search/web")
	u.RawQuery = url.Values{"qsi": {qsi}, "q": {"\"" + d.domain + "\""}}.Encode()

	return u.String()
}

func (d *dogpile) Search(done chan int) {
	done <- SearchQuery(d, d.subdomains)
	return
}

func DogpileSearch(domain string, subdomains chan *Subdomain) Searcher {
	d := new(dogpile)

	d.domain = domain
	// Dogpile returns roughly 15 results per page
	d.quantity = 15
	d.limit = 300
	d.subdomains = subdomains
	return d
}
