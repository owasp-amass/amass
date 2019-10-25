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

// ArchiveToday is the Service that handles access to the ArchiveToday data source.
type ArchiveToday struct {
	BaseService

	SourceType string
	domain     string
	baseURL    string
}

// NewArchiveToday returns he object initialized, but not yet started.
func NewArchiveToday(sys System) *ArchiveToday {
	a := &ArchiveToday{
		SourceType: requests.ARCHIVE,
		domain:     "archive.is",
		baseURL:    "http://archive.is",
	}

	a.BaseService = *NewBaseService(a, "ArchiveToday", sys)
	return a
}

// Type implements the Service interface.
func (a *ArchiveToday) Type() string {
	return a.SourceType
}

// OnStart implements the Service interface
func (a *ArchiveToday) OnStart() error {
	a.BaseService.OnStart()

	a.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (a *ArchiveToday) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
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
