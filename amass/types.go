// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
)

const (
	SMART   = "smart"
	FLIP    = "numflip"
	BRUTE   = "brute"
	SEARCH  = "search"
	ARCHIVE = "archive"
	DNSTag  = "dns"
	SHODAN  = "shodan"
)

type Searcher interface {
	Domain() string
	Quantity() int
	Limit() int
	URLByPageNum(page int) string
	Search(done chan int)
	fmt.Stringer
}

type Archiver interface {
	CheckHistory(subdomain *Subdomain)
	TotalUniqueSubdomains() int
	fmt.Stringer
}

type Guesser interface {
	AddName(name *Subdomain)
	Start()
}

type DNSChecker interface {
	CheckSubdomain(sd *Subdomain)
	TagQueriesFinished(tag string) bool
	AllQueriesFinished() bool
}

type Subdomain struct {
	Name, Domain, Address, Tag string
}
