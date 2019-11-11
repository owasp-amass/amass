// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// Exalead is the Service that handles access to the Exalead data source.
type Exalead struct {
	BaseService

	SourceType string
}

// NewExalead returns he object initialized, but not yet started.
func NewExalead(sys System) *Exalead {
	e := &Exalead{SourceType: requests.SCRAPE}

	e.BaseService = *NewBaseService(e, "Exalead", sys)
	return e
}

// Type implements the Service interface.
func (e *Exalead) Type() string {
	return e.SourceType
}

// OnStart implements the Service interface.
func (e *Exalead) OnStart() error {
	e.BaseService.OnStart()

	e.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (e *Exalead) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	e.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, e.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", e.String(), req.Domain))

	url := e.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", e.String(), url, err))
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: req.Domain,
			Tag:    e.SourceType,
			Source: e.String(),
		})
	}
}

func (e *Exalead) getURL(domain string) string {
	base := "http://www.exalead.com/search/web/results/"
	format := base + "?q=site:%s+-www?elements_per_page=50"

	return fmt.Sprintf(format, domain)
}
