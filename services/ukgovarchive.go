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

// UKGovArchive is the Service that handles access to the UKGovArchive data source.
type UKGovArchive struct {
	BaseService

	SourceType string
	domain     string
	baseURL    string
}

// NewUKGovArchive returns he object initialized, but not yet started.
func NewUKGovArchive(sys System) *UKGovArchive {
	u := &UKGovArchive{
		SourceType: requests.ARCHIVE,
		domain:     "webarchive.nationalarchives.gov.uk",
		baseURL:    "http://webarchive.nationalarchives.gov.uk",
	}

	u.BaseService = *NewBaseService(u, "UKGovArchive", sys)
	return u
}

// Type implements the Service interface.
func (u *UKGovArchive) Type() string {
	return u.SourceType
}

// OnStart implements the Service interface.
func (u *UKGovArchive) OnStart() error {
	u.BaseService.OnStart()

	u.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (u *UKGovArchive) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if req.Name == "" || req.Domain == "" || !cfg.IsDomainInScope(req.Name) {
		return
	}

	u.CheckRateLimit()

	names, err := crawl(ctx, u.baseURL, u.domain, req.Name, req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %v", u.String(), err))
		return
	}

	for _, name := range names {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: req.Domain,
			Tag:    u.SourceType,
			Source: u.String(),
		})
	}
}
