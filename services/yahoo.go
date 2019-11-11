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

// Yahoo is the Service that handles access to the Yahoo data source.
type Yahoo struct {
	BaseService

	SourceType string
	quantity   int
	limit      int
}

// NewYahoo returns he object initialized, but not yet started.
func NewYahoo(sys System) *Yahoo {
	y := &Yahoo{
		SourceType: requests.SCRAPE,
		quantity:   10,
		limit:      100,
	}

	y.BaseService = *NewBaseService(y, "Yahoo", sys)
	return y
}

// Type implements the Service interface.
func (y *Yahoo) Type() string {
	return y.SourceType
}

// OnStart implements the Service interface.
func (y *Yahoo) OnStart() error {
	y.BaseService.OnStart()

	y.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (y *Yahoo) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", y.String(), req.Domain))

	num := y.limit / y.quantity
	for i := 0; i < num; i++ {
		select {
		case <-y.Quit():
			return
		default:
			y.CheckRateLimit()
			bus.Publish(requests.SetActiveTopic, y.String())

			u := y.urlByPageNum(req.Domain, i)
			page, err := http.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", y.String(), u, err))
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   cleanName(sd),
					Domain: req.Domain,
					Tag:    y.SourceType,
					Source: y.String(),
				})
			}
		}
	}
}

func (y *Yahoo) urlByPageNum(domain string, page int) string {
	b := strconv.Itoa(y.quantity*page + 1)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("https://search.yahoo.com/search")
	u.RawQuery = url.Values{
		"p":     {"site:" + domain + " -domain:www." + domain},
		"b":     {b},
		"pz":    {pz},
		"bct":   {"0"},
		"xargs": {"0"},
	}.Encode()
	return u.String()
}
