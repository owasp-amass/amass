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

type DNSDB struct {
	BaseDataSource
	sync.Mutex
	filter map[string][]string
}

func NewDNSDB() DataSource {
	d := &DNSDB{filter: make(map[string][]string)}

	d.BaseDataSource = *NewBaseDataSource(SCRAPE, "DNSDB")
	return d
}

func (d *DNSDB) Query(domain, sub string) []string {
	d.Lock()
	defer d.Unlock()

	var unique []string

	dparts := strings.Split(domain, ".")
	sparts := strings.Split(sub, ".")

	name := sub
	if len(dparts) < len(sparts) {
		name = strings.Join(sparts[1:], ".")
	}

	if n, ok := d.filter[name]; ok {
		return n
	}
	d.filter[name] = unique

	url := d.getURL(domain, sub)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		d.log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}

	for _, rel := range d.getSubmatches(page) {
		// Do not go too fast
		time.Sleep(50 * time.Millisecond)
		// Pull the certificate web page
		another, err := utils.GetWebPage(url+rel, nil)
		if err != nil {
			d.log(fmt.Sprintf("%s: %v", url+rel, err))
			continue
		}

		for _, sd := range re.FindAllString(another, -1) {
			if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
				unique = append(unique, u...)
			}
		}
	}
	d.filter[name] = unique
	return unique
}

func (d *DNSDB) Subdomains() bool {
	return true
}

func (d *DNSDB) getURL(domain, sub string) string {
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

func (d *DNSDB) getSubmatches(content string) []string {
	var results []string

	re := regexp.MustCompile("<br/><a href=\"([a-z0-9])\">[a-z0-9]</a>")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		results = append(results, strings.TrimSpace(subs[1]))
	}
	return results
}
