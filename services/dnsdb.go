// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// DNSDB is the Service that handles access to the DNSDB data source.
type DNSDB struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewDNSDB returns he object initialized, but not yet started.
func NewDNSDB(sys System) *DNSDB {
	d := &DNSDB{SourceType: requests.SCRAPE}

	d.BaseService = *NewBaseService(d, "DNSDB", sys)
	return d
}

// Type implements the Service interface.
func (d *DNSDB) Type() string {
	return d.SourceType
}

// OnStart implements the Service interface.
func (d *DNSDB) OnStart() error {
	d.BaseService.OnStart()

	d.API = d.System().Config().GetAPIKey(d.String())
	if d.API == nil || d.API.Key == "" {
		d.System().Config().Log.Printf("%s: API key data was not provided", d.String())
	}

	d.SetRateLimit(500 * time.Millisecond)
	return nil
}

// OnDNSRequest implements the Service interface.
func (d *DNSDB) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	d.CheckRateLimit()
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", d.String(), req.Domain))

	if d.API != nil && d.API.Key != "" {
		headers := map[string]string{
			"X-API-KEY":    d.API.Key,
			"Accept":       "application/json",
			"Content-Type": "application/json",
		}

		url := d.restURL(req.Domain)
		page, err := http.RequestWebPage(url, nil, headers, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
			return
		}

		d.passiveDNSJSON(ctx, page, req.Domain)
		return
	}

	d.scrape(ctx, req.Domain)
}

func (d *DNSDB) restURL(domain string) string {
	return fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s", domain)
}

func (d *DNSDB) passiveDNSJSON(ctx context.Context, page, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(domain)
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
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.API,
			Source: d.String(),
		})
	}
}

func (d *DNSDB) scrape(ctx context.Context, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	url := d.getURL(domain, domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
		return
	}

	names := stringset.New()
	names.Union(d.followIndicies(ctx, page, domain))
	names.Union(d.pullPageNames(ctx, page, domain))

	// Share what has been discovered so far
	for name := range names {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.SCRAPE,
			Source: d.String(),
		})
	}

loop:
	for name := range names {
		select {
		case <-d.Quit():
			break loop
		default:
			if name == domain {
				continue loop
			}

			d.CheckRateLimit()

			url = d.getURL(domain, name)
			another, err := http.RequestWebPage(url, nil, nil, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
				continue loop
			}

			for result := range d.pullPageNames(ctx, another, domain) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
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

func (d *DNSDB) followIndicies(ctx context.Context, page, domain string) stringset.Set {
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

		unique.Union(d.pullPageNames(ctx, ipage, domain))
		d.CheckRateLimit()
	}
	return unique
}

func (d *DNSDB) pullPageNames(ctx context.Context, page, domain string) stringset.Set {
	names := stringset.New()

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return names
	}

	if re := cfg.DomainRegex(domain); re != nil {
		for _, name := range re.FindAllString(page, -1) {
			names.Insert(cleanName(name))
		}
	}
	return names
}
