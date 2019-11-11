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

// BufferOver is the Service that handles access to the BufferOver data source.
type BufferOver struct {
	BaseService

	SourceType string
}

// NewBufferOver returns he object initialized, but not yet started.
func NewBufferOver(sys System) *BufferOver {
	b := &BufferOver{SourceType: requests.API}

	b.BaseService = *NewBaseService(b, "BufferOver", sys)
	return b
}

// Type implements the Service interface.
func (b *BufferOver) Type() string {
	return b.SourceType
}

// OnStart implements the Service interface.
func (b *BufferOver) OnStart() error {
	b.BaseService.OnStart()

	b.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (b *BufferOver) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	b.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, b.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", b.String(), req.Domain))

	url := b.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", b.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
			Tag:    b.SourceType,
			Source: b.String(),
		})
	}
}

func (b *BufferOver) getURL(domain string) string {
	format := "https://dns.bufferover.run/dns?q=.%s"

	return fmt.Sprintf(format, domain)
}
