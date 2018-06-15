// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	DNSDBSourceString string = "DNSDB"
)

var (
	dnsdbFilter map[string][]string
	dnsdbLock   sync.Mutex
)

func init() {
	dnsdbFilter = make(map[string][]string)
}

func DNSDBQuery(domain, sub string) []string {
	dnsdbLock.Lock()
	defer dnsdbLock.Unlock()

	var unique []string

	dparts := strings.Split(domain, ".")
	sparts := strings.Split(sub, ".")

	name := sub
	if len(dparts) < len(sparts) {
		name = strings.Join(sparts[1:], ".")
	}

	if n, ok := dnsdbFilter[name]; ok {
		return n
	}
	dnsdbFilter[name] = unique

	url := dnsdbURL(domain, sub)
	page := utils.GetWebPage(url, nil)
	if page == "" {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}

	for _, rel := range dnsdbGetSubmatches(page) {
		// Do not go too fast
		time.Sleep(50 * time.Millisecond)
		// Pull the certificate web page
		another := utils.GetWebPage(url+rel, nil)
		if another == "" {
			continue
		}

		for _, sd := range re.FindAllString(another, -1) {
			if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
				unique = append(unique, u...)
			}
		}
	}
	dnsdbFilter[name] = unique
	return unique
}

func dnsdbURL(domain, sub string) string {
	format := "http://www.dnsdb.org/%s/"
	url := fmt.Sprintf(format, domain)
	dparts := strings.Split(domain, ".")
	sparts := strings.Split(sub, ".")

	if len(dparts) == len(sparts) {
		return url
	}

	delta := len(sparts) - len(dparts)
	for i := delta - 1; i >= 0; i-- {
		url += sparts[i] + "/"
	}
	return url
}

func dnsdbGetSubmatches(content string) []string {
	var results []string

	re := regexp.MustCompile("<br/><a href=\"([a-z0-9])\">[a-z0-9]</a>")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		results = append(results, strings.TrimSpace(subs[1]))
	}
	return results
}
