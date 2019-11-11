// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// HackerTarget is the Service that handles access to the HackerTarget data source.
type HackerTarget struct {
	BaseService

	SourceType string
}

// NewHackerTarget returns he object initialized, but not yet started.
func NewHackerTarget(sys System) *HackerTarget {
	h := &HackerTarget{SourceType: requests.API}

	h.BaseService = *NewBaseService(h, "HackerTarget", sys)
	return h
}

// Type implements the Service interface.
func (h *HackerTarget) Type() string {
	return h.SourceType
}

// OnStart implements the Service interface.
func (h *HackerTarget) OnStart() error {
	h.BaseService.OnStart()

	h.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (h *HackerTarget) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
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

func (h *HackerTarget) getDNSURL(domain string) string {
	format := "http://api.hackertarget.com/hostsearch/?q=%s"

	return fmt.Sprintf(format, domain)
}

// OnASNRequest implements the Service interface.
func (h *HackerTarget) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	if req == nil || req.Address == "" {
		return
	}

	h.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, h.String())

	url := h.getASNURL(req.Address)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", h.String(), url, err))
		return
	}

	fields := strings.Split(page, ",")
	if len(fields) < 4 {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: Failed to parse the response", h.String(), url))
		return
	}

	asn, err := strconv.Atoi(strings.Trim(fields[1], "\""))
	if err != nil {
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to parse the origin response: %v", h.String(), url, err),
		)
		return
	}

	bus.Publish(requests.NewASNTopic, &requests.ASNRequest{
		Address:        req.Address,
		ASN:            asn,
		Prefix:         strings.Trim(fields[2], "\""),
		AllocationDate: time.Now(),
		Description:    strings.Trim(fields[3], "\""),
		Netblocks:      stringset.New(strings.Trim(fields[2], "\"")),
		Tag:            h.SourceType,
		Source:         h.String(),
	})
}

func (h *HackerTarget) getASNURL(addr string) string {
	format := "https://api.hackertarget.com/aslookup/?q=%s"

	return fmt.Sprintf(format, addr)
}
