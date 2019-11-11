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

// Google is the Service that handles access to the Google search engine data source.
type Google struct {
	BaseService

	SourceType string
	quantity   int
	limit      int
}

// NewGoogle returns he object initialized, but not yet started.
func NewGoogle(sys System) *Google {
	g := &Google{
		SourceType: requests.SCRAPE,
		quantity:   10,
		limit:      100,
	}

	g.BaseService = *NewBaseService(g, "Google", sys)
	return g
}

// Type implements the Service interface.
func (g *Google) Type() string {
	return g.SourceType
}

// OnStart implements the Service interface.
func (g *Google) OnStart() error {
	g.BaseService.OnStart()

	g.SetRateLimit(3 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (g *Google) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	for i := 0; i <= 3; i++ {
		g.executeQuery(ctx, req.Domain, i)
	}
}

func (g *Google) executeQuery(ctx context.Context, domain string, numwilds int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(domain)
	if re == nil {
		return
	}

	if numwilds == 0 {
		bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", g.String(), domain))
	}

	num := g.limit / g.quantity
	for i := 0; i < num; i++ {
		select {
		case <-g.Quit():
			return
		default:
			g.CheckRateLimit()
			bus.Publish(requests.SetActiveTopic, g.String())

			u := g.urlByPageNum(domain, i, numwilds)
			page, err := http.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", g.String(), u, err))
				return
			}

			for _, name := range re.FindAllString(page, -1) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   cleanName(name),
					Domain: domain,
					Tag:    g.SourceType,
					Source: g.String(),
				})
			}
		}
	}
}

func (g *Google) urlByPageNum(domain string, page, numwilds int) string {
	start := strconv.Itoa(g.quantity * page)
	u, _ := url.Parse("https://www.google.com/search")

	var wilds string
	for i := 0; i < numwilds; i++ {
		wilds = "*." + wilds
	}

	u.RawQuery = url.Values{
		"q":      {"site:" + wilds + domain + " -www.*"},
		"btnG":   {"Search"},
		"hl":     {"en"},
		"biw":    {""},
		"bih":    {""},
		"gbv":    {"1"},
		"start":  {start},
		"filter": {"0"},
	}.Encode()
	return u.String()
}
