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

// Netcraft is the Service that handles access to the Netcraft data source.
type Netcraft struct {
	BaseService

	SourceType string
}

// NewNetcraft returns he object initialized, but not yet started.
func NewNetcraft(sys System) *Netcraft {
	n := &Netcraft{SourceType: requests.SCRAPE}

	n.BaseService = *NewBaseService(n, "Netcraft", sys)
	return n
}

// Type implements the Service interface.
func (n *Netcraft) Type() string {
	return n.SourceType
}

// OnStart implements the Service interface.
func (n *Netcraft) OnStart() error {
	n.BaseService.OnStart()

	n.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (n *Netcraft) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	n.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, n.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", n.String(), req.Domain))

	url := n.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", n.String(), url, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
			Tag:    n.SourceType,
			Source: n.String(),
		})
	}
}

func (n *Netcraft) getURL(domain string) string {
	format := "https://searchdns.netcraft.com/?restriction=site+ends+with&host=%s"

	return fmt.Sprintf(format, domain)
}
