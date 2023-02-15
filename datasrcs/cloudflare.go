// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package datasrcs

import (
	"context"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/service"
	"github.com/cloudflare/cloudflare-go"
)

// Cloudflare is the Service that handles access to the Cloudflare data source.
type Cloudflare struct {
	service.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

// NewCloudflare returns he object initialized, but not yet started.
func NewCloudflare(sys systems.System) *Cloudflare {
	c := &Cloudflare{
		SourceType: requests.API,
		sys:        sys,
	}

	go c.requests()
	c.BaseService = *service.NewBaseService(c, "Cloudflare")
	return c
}

// Description implements the Service interface.
func (c *Cloudflare) Description() string {
	return c.SourceType
}

// OnStart implements the Service interface.
func (c *Cloudflare) OnStart() error {
	c.creds = c.sys.Config().GetDataSourceConfig(c.String()).GetCredentials()

	if c.creds == nil || c.creds.Key == "" {
		c.sys.Config().Log.Printf("%s: API key data was not provided", c.String())
	}

	c.SetRateLimit(2)
	return nil
}

func (c *Cloudflare) requests() {
	for {
		select {
		case <-c.Done():
			return
		case in := <-c.Input():
			switch req := in.(type) {
			case *requests.DNSRequest:
				c.CheckRateLimit()
				c.dnsRequest(context.TODO(), req)
			}
		}
	}
}

func (c *Cloudflare) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	if c.creds == nil || c.creds.Key == "" {
		return
	}

	if !c.sys.Config().IsDomainInScope(req.Domain) {
		return
	}

	c.sys.Config().Log.Printf("Querying %s for %s subdomains", c.String(), req.Domain)

	api, err := cloudflare.NewWithAPIToken(c.creds.Key)
	if err != nil {
		c.sys.Config().Log.Printf("%s: %v", c.String(), err)
	}

	zones, err := api.ListZones(ctx, req.Domain)
	if err != nil {
		c.sys.Config().Log.Printf("%s: %v", c.String(), err)
	}

	for _, zone := range zones {
		records, err := api.DNSRecords(ctx, zone.ID, cloudflare.DNSRecord{})
		if err != nil {
			c.sys.Config().Log.Printf("%s: %v", c.String(), err)
		}

		for _, record := range records {
			if d := c.sys.Config().WhichDomain(record.Name); d != "" {
				c.Output() <- &requests.DNSRequest{
					Name:   record.Name,
					Domain: req.Domain,
					Tag:    c.SourceType,
					Source: c.String(),
				}
			}
			if record.Type == "CNAME" {
				if d := c.sys.Config().WhichDomain(record.Content); d != "" {
					c.Output() <- &requests.DNSRequest{
						Name:   record.Content,
						Domain: req.Domain,
						Tag:    c.SourceType,
						Source: c.String(),
					}
				}
			}
		}
	}
}
