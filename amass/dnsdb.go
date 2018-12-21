// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// DNSDB is the Service that handles access to the DNSDB data source.
type DNSDB struct {
	BaseService

	API        *APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewDNSDB returns he object initialized, but not yet started.
func NewDNSDB(e *Enumeration) *DNSDB {
	d := &DNSDB{
		SourceType: SCRAPE,
		RateLimit:  time.Second,
	}

	d.BaseService = *NewBaseService(e, "DNSDB", d)
	return d
}

// OnStart implements the Service interface
func (d *DNSDB) OnStart() error {
	d.BaseService.OnStart()

	d.API = d.Enum().Config.GetAPIKey(d.String())
	if d.API == nil || d.API.Key == "" {
		d.Enum().Log.Printf("%s: API key data was not provided", d.String())
	}
	go d.startRootDomains()
	go d.processRequests()
	return nil
}

func (d *DNSDB) processRequests() {
	for {
		select {
		case <-d.PauseChan():
			<-d.ResumeChan()
		case <-d.Quit():
			return
		case <-d.RequestChan():
			// This data source just throws away the checked DNS names
			d.SetActive()
		}
	}
}

func (d *DNSDB) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range d.Enum().Config.Domains() {
		d.executeQuery(domain)
		// Honor the rate limit
		time.Sleep(d.RateLimit)
	}
}

func (d *DNSDB) executeQuery(domain string) {
	if d.API != nil && d.API.Key != "" {
		headers := map[string]string{
			"X-API-KEY":    d.API.Key,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}

		url := d.restURL(domain)
		page, err := utils.RequestWebPage(url, nil, headers, "", "")
		if err != nil {
			d.Enum().Log.Printf("%s: %s: %v", d.String(), url, err)
			return
		}

		d.passiveDNSJSON(page, domain)
		return
	}
	d.scrape(domain)
}

func (d *DNSDB) restURL(domain string) string {
	return fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s", domain)
}

func (d *DNSDB) passiveDNSJSON(page, domain string) {
	var unique []string

	d.SetActive()
	re := d.Enum().Config.DomainRegex(domain)
	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j struct {
			Name string `json:"rrname"`
		}
		err := json.Unmarshal([]byte(line), &j)
		if err != nil {
			continue
		}
		if re.MatchString(j.Name) {
			unique = utils.UniqueAppend(unique, j.Name)
		}
	}

	for _, name := range unique {
		d.Enum().NewNameEvent(&Request{
			Name:   name,
			Domain: domain,
			Tag:    API,
			Source: d.String(),
		})
	}
}

func (d *DNSDB) scrape(domain string) {
	url := d.getURL(domain, domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Enum().Log.Printf("%s: %s: %v", d.String(), url, err)
		return
	}

	var names []string
	if f := d.followIndicies(page, domain); len(f) > 0 {
		names = utils.UniqueAppend(names, f...)
	} else if n := d.pullPageNames(page, domain); len(n) > 0 {
		names = utils.UniqueAppend(names, n...)
	}
	// Share what has been discovered so far
	for _, name := range names {
		d.Enum().NewNameEvent(&Request{
			Name:   name,
			Domain: domain,
			Tag:    SCRAPE,
			Source: d.String(),
		})
	}

	t := time.NewTicker(d.RateLimit)
	defer t.Stop()
loop:
	for _, name := range names {
		d.SetActive()

		select {
		case <-d.Quit():
			break loop
		case <-t.C:
			if name == domain {
				continue
			}

			url = d.getURL(domain, name)
			another, err := utils.RequestWebPage(url, nil, nil, "", "")
			if err != nil {
				d.Enum().Log.Printf("%s: %s: %v", d.String(), url, err)
				continue
			}

			for _, result := range d.pullPageNames(another, domain) {
				d.Enum().NewNameEvent(&Request{
					Name:   result,
					Domain: domain,
					Tag:    SCRAPE,
					Source: d.String(),
				})
			}
		}
	}
}

func (d *DNSDB) getURL(domain, sub string) string {
	url := fmt.Sprintf("https://www.dnsdb.org/%s/", domain)
	dlen := len(strings.Split(domain, "."))
	sparts := strings.Split(sub, ".")
	slen := len(sparts)
	if dlen == slen {
		return url
	}

	for i := (slen - dlen) - 1; i >= 0; i-- {
		url += sparts[i] + "/"
	}
	return url
}

var dnsdbIndexRE = regexp.MustCompile(`<a href="[a-zA-Z0-9]">([a-zA-Z0-9])</a>`)

func (d *DNSDB) followIndicies(page, domain string) []string {
	var indicies, unique []string
	idx := dnsdbIndexRE.FindAllStringSubmatch(page, -1)
	if idx == nil {
		return unique
	}

	for _, match := range idx {
		if match[1] == "" {
			continue
		}
		indicies = append(indicies, match[1])
	}

	for _, idx := range indicies {
		url := fmt.Sprintf("https://www.dnsdb.org/%s/%s", domain, idx)
		ipage, err := utils.RequestWebPage(url, nil, nil, "", "")
		if err != nil {
			continue
		}

		if names := d.pullPageNames(ipage, domain); len(names) > 0 {
			unique = utils.UniqueAppend(unique, names...)
		}
		time.Sleep(d.RateLimit)
	}
	return unique
}

func (d *DNSDB) pullPageNames(page, domain string) []string {
	var names []string

	d.SetActive()
	re := d.Enum().Config.DomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(names, cleanName(sd)); len(u) > 0 {
			names = append(names, u...)
		}
	}
	return names
}
