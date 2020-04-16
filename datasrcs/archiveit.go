// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"fmt"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
)

// ArchiveIt is the Service that handles access to the ArchiveIt data source.
type ArchiveIt struct {
	requests.BaseService

	SourceType string
	domain     string
	baseURL    string
}

// NewArchiveIt returns he object initialized, but not yet started.
func NewArchiveIt(sys systems.System) *ArchiveIt {
	a := &ArchiveIt{
		SourceType: requests.ARCHIVE,
		domain:     "wayback.archive-it.org",
		baseURL:    "https://wayback.archive-it.org/all",
	}

	a.BaseService = *requests.NewBaseService(a, "ArchiveIt")
	return a
}

// Type implements the Service interface.
func (a *ArchiveIt) Type() string {
	return a.SourceType
}

// OnStart implements the Service interface.
func (a *ArchiveIt) OnStart() error {
	a.BaseService.OnStart()

	a.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (a *ArchiveIt) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
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
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", a.String(), err))
		return
	}

	for _, name := range names {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: req.Domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}
}
