// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
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

	d.SetRateLimit(2 * time.Minute)
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

	if d.API == nil || d.API.Key == "" {
		return
	}

	d.CheckRateLimit()
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", d.String(), req.Domain))

	headers := map[string]string{
		"X-API-Key":    d.API.Key,
		"Accept":       "application/json",
		"Content-Type": "application/json",
	}

	url := d.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", d.String(), url, err))
		return
	}

	for _, name := range d.parse(ctx, page, req.Domain) {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    requests.API,
			Source: d.String(),
		})
	}
}

func (d *DNSDB) getURL(domain string) string {
	return fmt.Sprintf("https://api.dnsdb.info/lookup/rrset/name/*.%s", domain)
}

func (d *DNSDB) parse(ctx context.Context, page, domain string) []string {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return []string{}
	}

	re := cfg.DomainRegex(domain)
	if re == nil {
		return []string{}
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

	return unique.Slice()
}
