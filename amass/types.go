// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"fmt"
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
	CheckHistory(subdomain string)
	TotalUniqueSubdomains() int
	fmt.Stringer
}

type DNSChecker interface {
	CheckSubdomain(sd string)
	CheckSubdomains(sds []string)
}

type ValidSubdomain struct {
	Subdomain string
	Address   string
}
