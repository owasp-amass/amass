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

// HackerOne is the Service that handles access to the unofficial
// HackerOne disclosure timeline data source.
type HackerOne struct {
	BaseService

	SourceType string
}

// NewHackerOne returns he object initialized, but not yet started.
func NewHackerOne(sys System) *HackerOne {
	h := &HackerOne{SourceType: requests.API}

	h.BaseService = *NewBaseService(h, "HackerOne", sys)
	return h
}

// Type implements the Service interface.
func (h *HackerOne) Type() string {
	return h.SourceType
}

// OnStart implements the Service interface.
func (h *HackerOne) OnStart() error {
	h.BaseService.OnStart()

	h.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (h *HackerOne) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	h.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, h.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", h.String(), req.Domain))

	url := h.getDNSURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", h.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
			Tag:    h.SourceType,
			Source: h.String(),
		})
	}
}

func (h *HackerOne) getDNSURL(domain string) string {
	format := "http://h1.nobbd.de/search.php?q=%s"

	return fmt.Sprintf(format, domain)
}
