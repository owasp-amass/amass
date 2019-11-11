// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// Bing is the Service that handles access to the Bing data source.
type Bing struct {
	BaseService

	SourceType string
	quantity   int
	limit      int
}

// NewBing returns he object initialized, but not yet started.
func NewBing(sys System) *Bing {
	b := &Bing{
		SourceType: requests.SCRAPE,
		quantity:   20,
		limit:      200,
	}

	b.BaseService = *NewBaseService(b, "Bing", sys)
	return b
}

// Type implements the Service interface.
func (b *Bing) Type() string {
	return b.SourceType
}

// OnStart implements the Service interface.
func (b *Bing) OnStart() error {
	b.BaseService.OnStart()

	b.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (b *Bing) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", b.String(), req.Domain))

	num := b.limit / b.quantity
	for i := 0; i < num; i++ {
		select {
		case <-b.Quit():
			return
		default:
			b.CheckRateLimit()
			bus.Publish(requests.SetActiveTopic, b.String())

			u := b.urlByPageNum(req.Domain, i)
			page, err := http.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", b.String(), u, err))
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
	}
}

func (b *Bing) urlByPageNum(domain string, page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{
		"q":     {"domain:" + domain + " -www." + domain},
		"count": {count},
		"first": {first},
		"FORM":  {"PORE"},
	}.Encode()
	return u.String()
}
