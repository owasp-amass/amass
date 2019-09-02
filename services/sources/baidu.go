// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/net/http"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
)

// Baidu is the Service that handles access to the Baidu data source.
type Baidu struct {
	services.BaseService

	SourceType string
	quantity   int
	limit      int
}

// NewBaidu returns he object initialized, but not yet started.
func NewBaidu(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Baidu {
	b := &Baidu{
		SourceType: requests.SCRAPE,
		quantity:   20,
		limit:      100,
	}

	b.BaseService = *services.NewBaseService(b, "Baidu", cfg, bus, pool)
	return b
}

// OnStart implements the Service interface
func (b *Baidu) OnStart() error {
	b.BaseService.OnStart()

	go b.processRequests()
	return nil
}

func (b *Baidu) processRequests() {
	for {
		select {
		case <-b.Quit():
			return
		case req := <-b.DNSRequestChan():
			if b.Config().IsDomainInScope(req.Domain) {
				b.executeQuery(req.Domain)
			}
		case <-b.AddrRequestChan():
		case <-b.ASNRequestChan():
		case <-b.WhoisRequestChan():
		}
	}
}

func (b *Baidu) executeQuery(domain string) {
	re := b.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	num := b.limit / b.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for i := 0; i < num; i++ {
		b.SetActive()

		select {
		case <-b.Quit():
			return
		case <-t.C:
			u := b.urlByPageNum(domain, i)
			page, err := http.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				b.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", b.String(), u, err))
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				b.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    b.SourceType,
					Source: b.String(),
				})
			}
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
