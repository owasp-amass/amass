// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
)

type pgp struct {
	domain     string
	subdomains chan *Subdomain
}

func (p pgp) String() string {
	return "PGP Search"
}

func (p pgp) Domain() string {
	return p.domain
}

func (p pgp) Quantity() int {
	return 1
}

func (p pgp) Limit() int {
	return 1
}

func (p pgp) URLByPageNum(page int) string {
	u, _ := url.Parse("http://pgp.mit.edu/pks/lookup")
	u.RawQuery = url.Values{"search": {p.domain}, "op": {"index"}}.Encode()

	return u.String()
}

func (p *pgp) Search(done chan int) {
	done <- SearchQuery(p, p.subdomains)
	return
}

func PGPSearch(domain string, subdomains chan *Subdomain) Searcher {
	p := new(pgp)

	p.domain = domain
	p.subdomains = subdomains
	return p
}
