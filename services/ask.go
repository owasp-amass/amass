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

// Ask is the Service that handles access to the Ask data source.
type Ask struct {
	BaseService

	SourceType string
	quantity   int
	limit      int
}

// NewAsk returns he object initialized, but not yet started.
func NewAsk(sys System) *Ask {
	a := &Ask{
		SourceType: requests.SCRAPE,
		quantity:   10, // ask.com appears to be hardcoded at 10 results per page
		limit:      100,
	}

	a.BaseService = *NewBaseService(a, "Ask", sys)
	return a
}

// Type implements the Service interface.
func (a *Ask) Type() string {
	return a.SourceType
}

// OnStart implements the Service interface.
func (a *Ask) OnStart() error {
	a.BaseService.OnStart()

	a.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (a *Ask) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", a.String(), req.Domain))

	num := a.limit / a.quantity
	for i := 0; i < num; i++ {
		select {
		case <-a.Quit():
			return
		default:
			a.CheckRateLimit()
			bus.Publish(requests.SetActiveTopic, a.String())

			u := a.urlByPageNum(req.Domain, i)
			page, err := http.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   cleanName(sd),
					Domain: req.Domain,
					Tag:    a.SourceType,
					Source: a.String(),
				})
			}
		}
	}
}

func (a *Ask) urlByPageNum(domain string, page int) string {
	p := strconv.Itoa(page)
	u, _ := url.Parse("https://www.ask.com/web")

	u.RawQuery = url.Values{
		"q":    {"site:" + domain + " -www." + domain},
		"o":    {"0"},
		"l":    {"dir"},
		"qo":   {"pagination"},
		"page": {p},
	}.Encode()
	return u.String()
}
