// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/requests"
)

// Arquivo is the Service that handles access to the Arquivo data source.
type Arquivo struct {
	BaseService

	SourceType string
	domain     string
	baseURL    string
}

// NewArquivo returns he object initialized, but not yet started.
func NewArquivo(sys System) *Arquivo {
	a := &Arquivo{
		SourceType: requests.ARCHIVE,
		domain:     "arquivo.pt",
		baseURL:    "http://arquivo.pt/wayback",
	}

	a.BaseService = *NewBaseService(a, "Arquivo", sys)
	return a
}

// Type implements the Service interface.
func (a *Arquivo) Type() string {
	return a.SourceType
}

// OnStart implements the Service interface.
func (a *Arquivo) OnStart() error {
	a.BaseService.OnStart()

	a.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (a *Arquivo) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if req.Name == "" || req.Domain == "" || !cfg.IsDomainInScope(req.Name) {
		return
	}

	a.CheckRateLimit()

	names, err := crawl(ctx, a.baseURL, a.domain, req.Name, req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %v", a.String(), err))
		return
	}

	for _, name := range names {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: req.Domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}
}
