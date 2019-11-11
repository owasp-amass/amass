// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// Baidu is the Service that handles access to the Baidu data source.
type Baidu struct {
	BaseService

	SourceType string
	quantity   int
	limit      int
}

// NewBaidu returns he object initialized, but not yet started.
func NewBaidu(sys System) *Baidu {
	b := &Baidu{
		SourceType: requests.SCRAPE,
		quantity:   20,
		limit:      100,
	}

	b.BaseService = *NewBaseService(b, "Baidu", sys)
	return b
}

// Type implements the Service interface.
func (b *Baidu) Type() string {
	return b.SourceType
}

// OnStart implements the Service interface.
func (b *Baidu) OnStart() error {
	b.BaseService.OnStart()

	b.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (b *Baidu) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
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
					Tag:    b.Type(),
					Source: b.String(),
				})
			}
		}
	}

	b.CheckRateLimit()
	// Check for related sites known by Baidu
	u := b.urlForRelatedSites(req.Domain)
	page, err := http.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", b.String(), u, err))
		return
	}

	// Extract the related site information
	var rs struct {
		Code int `json:"code"`
		Data []struct {
			Domain string `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(page), &rs); err != nil || rs.Code != 0 {
		return
	}

	for _, element := range rs.Data {
		if d := cfg.WhichDomain(element.Domain); d != "" {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   element.Domain,
				Domain: d,
				Tag:    b.Type(),
				Source: b.String(),
			})
		}
	}
}

func (b *Baidu) urlByPageNum(domain string, page int) string {
	pn := strconv.Itoa(page)
	u, _ := url.Parse("https://www.baidu.com/s")
	query := "site:" + domain + " -site:www." + domain

	u.RawQuery = url.Values{
		"pn": {pn},
		"wd": {query},
		"oq": {query},
	}.Encode()
	return u.String()
}

func (b *Baidu) urlForRelatedSites(domain string) string {
	u, _ := url.Parse("https://ce.baidu.com/index/getRelatedSites")

	u.RawQuery = url.Values{"site_address": {domain}}.Encode()
	return u.String()
}
