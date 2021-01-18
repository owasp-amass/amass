// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
)

// Pastebin is the Service that handles access to the Pastebin data source.
type Pastebin struct {
	service.BaseService

	SourceType string
	sys        systems.System
}

// NewPastebin returns he object initialized, but not yet started.
func NewPastebin(sys systems.System) *Pastebin {
	p := &Pastebin{
		SourceType: requests.API,
		sys:        sys,
	}

	p.BaseService = *service.NewBaseService(p, "Pastebin")
	return p
}

// Description implements the Service interface.
func (p *Pastebin) Description() string {
	return p.SourceType
}

// OnStart implements the Service interface.
func (p *Pastebin) OnStart() error {
	p.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (p *Pastebin) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.DNSRequest); ok {
		p.dnsRequest(ctx, req)
	}
}

func (p *Pastebin) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	numRateLimitChecks(p, 2)
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", p.String(), req.Domain))

	ids, err := p.extractIDs(req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: %v", p.String(), req.Domain, err))
		return
	}

	for _, id := range ids {
		url := p.webURLDumpData(id)
		page, err := http.RequestWebPage(url, nil, nil, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", p.String(), url, err))
			return
		}

		for _, name := range re.FindAllString(page, -1) {
			genNewNameEvent(ctx, p.sys, p, name)
		}
	}
}

// Extract the IDs from the pastebin Web response.
func (p *Pastebin) extractIDs(domain string) ([]string, error) {
	url := p.webURLDumpIDs(domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		return nil, err
	}

	// Extract the response given by pastebin
	var d struct {
		Search string `json:"search"`
		Count  int    `json:"count"`
		Items  []struct {
			ID   string `json:"id"`
			Tags string `json:"tags"`
			Time string `json:"time"`
		} `json:"data"`
	}
	err = json.Unmarshal([]byte(page), &d)
	if err != nil {
		return nil, err
	}

	var ids []string
	for _, item := range d.Items {
		ids = append(ids, item.ID)
	}

	return ids, nil
}

// Returns the Web URL to fetch all dump ids for a given doamin.
func (p *Pastebin) webURLDumpIDs(domain string) string {
	return fmt.Sprintf("https://psbdmp.ws/api/search/%s", domain)
}

// Returns the Web URL to get all dumps for a given doamin.
func (p *Pastebin) webURLDumpData(id string) string {
	return fmt.Sprintf("https://psbdmp.ws/api/dump/get/%s", id)
}
