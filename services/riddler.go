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

// Riddler is the Service that handles access to the Riddler data source.
type Riddler struct {
	BaseService

	SourceType string
}

// NewRiddler returns he object initialized, but not yet started.
func NewRiddler(sys System) *Riddler {
	r := &Riddler{SourceType: requests.SCRAPE}

	r.BaseService = *NewBaseService(r, "Riddler", sys)
	return r
}

// Type implements the Service interface.
func (r *Riddler) Type() string {
	return r.SourceType
}

// OnStart implements the Service interface.
func (r *Riddler) OnStart() error {
	r.BaseService.OnStart()

	r.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (r *Riddler) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, r.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", r.String(), req.Domain))

	url := r.getURL(req.Domain)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	for _, name := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(name),
			Domain: req.Domain,
			Tag:    r.SourceType,
			Source: r.String(),
		})
	}
}

func (r *Riddler) getURL(domain string) string {
	format := "https://riddler.io/search?q=pld:%s"

	return fmt.Sprintf(format, domain)
}
