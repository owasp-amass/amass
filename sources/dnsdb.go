// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/stringset"
)

// DNSDB is the Service that handles access to the DNSDB data source.
type DNSDB struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewDNSDB returns he object initialized, but not yet started.
func NewDNSDB(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *DNSDB {
	d := &DNSDB{
		SourceType: requests.SCRAPE,
		RateLimit:  500 * time.Millisecond,
	}

	d.BaseService = *services.NewBaseService(d, "DNSDB", cfg, bus, pool)
	return d
}

// OnStart implements the Service interface
func (d *DNSDB) OnStart() error {
	d.BaseService.OnStart()

	d.API = d.Config().GetAPIKey(d.String())
	if d.API == nil || d.API.Key == "" {
		d.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: API key data was not provided", d.String()))
	}

	go d.processRequests()
	return nil
}

func (d *DNSDB) processRequests() {
	last := time.Now()

	for {
		select {
		case <-d.Quit():
			return
		case req := <-d.DNSRequestChan():
			if d.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < d.RateLimit {
					time.Sleep(d.RateLimit)
				}

				d.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-d.AddrRequestChan():
		case <-d.ASNRequestChan():
		case <-d.WhoisRequestChan():
		}
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
		page, err := http.RequestWebPage(url, nil, headers, "", "")
		if err != nil {
			d.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
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

	re := d.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	unique := stringset.New()
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
			unique.Insert(j.Name)
		}
	}

	for name := range unique {
		d.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.API,
			Source: d.String(),
		})
	}
}

func (d *DNSDB) scrape(domain string) {
	url := d.getURL(domain, domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		d.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
		return
	}

	names := stringset.New()
	names.Union(d.followIndicies(page, domain))
	names.Union(d.pullPageNames(page, domain))

	// Share what has been discovered so far
	for name := range names {
		d.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.SCRAPE,
			Source: d.String(),
		})
	}

	t := time.NewTicker(d.RateLimit)
	defer t.Stop()
loop:
	for name := range names {
		select {
		case <-d.Quit():
			break loop
		case <-t.C:
			if name == domain {
				continue
			}

			url = d.getURL(domain, name)
			another, err := http.RequestWebPage(url, nil, nil, "", "")
			if err != nil {
				d.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
				continue
			}

			for result := range d.pullPageNames(another, domain) {
				d.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   result,
					Domain: domain,
					Tag:    requests.SCRAPE,
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

func (d *DNSDB) followIndicies(page, domain string) stringset.Set {
	var indicies []string
	unique := stringset.New()
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
		ipage, err := http.RequestWebPage(url, nil, nil, "", "")
		if err != nil {
			continue
		}

		unique.Union(d.pullPageNames(ipage, domain))
		time.Sleep(d.RateLimit)
	}
	return unique
}

func (d *DNSDB) pullPageNames(page, domain string) stringset.Set {
	names := stringset.New()

	if re := d.Config().DomainRegex(domain); re != nil {
		for _, name := range re.FindAllString(page, -1) {
			names.Insert(cleanName(name))
		}
	}
	return names
}
