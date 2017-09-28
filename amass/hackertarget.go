// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
)

type hackertarget struct {
	domain     string
	subdomains chan string
}

func (h hackertarget) String() string {
	return "HackerTarget Search"
}

func (h hackertarget) Domain() string {
	return h.domain
}

func (h hackertarget) Quantity() int {
	return 1
}

func (h hackertarget) Limit() int {
	return 1
}

func (h hackertarget) URLByPageNum(page int) string {
	u, _ := url.Parse("http://api.hackertarget.com/hostsearch/")
	u.RawQuery = url.Values{"q": {h.domain}}.Encode()

	return u.String()
}

func (h *hackertarget) Search(done chan int) {
	done <- SearchQuery(h, h.subdomains)
	return
}

func HackerTargetSearch(domain string, subdomains chan string) Searcher {
	h := new(hackertarget)

	h.domain = domain
	h.subdomains = subdomains
	return h
}
