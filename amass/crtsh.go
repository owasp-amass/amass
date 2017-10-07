// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
)

type crtsh struct {
	domain     string
	subdomains chan *Subdomain
}

func (c crtsh) String() string {
	return "Crtsh Search"
}

func (c crtsh) Domain() string {
	return c.domain
}

func (c crtsh) Quantity() int {
	return 1
}

func (c crtsh) Limit() int {
	return 1
}

func (c crtsh) URLByPageNum(page int) string {
	u, _ := url.Parse("https://crt.sh/")
	u.RawQuery = url.Values{"q": {"%25" + c.domain}}.Encode()

	return u.String()
}

func (c *crtsh) Search(done chan int) {
	done <- SearchQuery(c, c.subdomains)
	return
}

func CrtshSearch(domain string, subdomains chan *Subdomain) Searcher {
	c := new(crtsh)

	c.domain = domain
	c.subdomains = subdomains
	return c
}
