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
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// Bing is the Service that handles access to the Bing data source.
type Bing struct {
	services.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewBing returns he object initialized, but not yet started.
func NewBing(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Bing {
	b := &Bing{
		quantity:   20,
		limit:      200,
		SourceType: requests.SCRAPE,
	}

	b.BaseService = *services.NewBaseService(b, "Bing", cfg, bus, pool)
	return b
}

// OnStart implements the Service interface
func (b *Bing) OnStart() error {
	b.BaseService.OnStart()

	go b.processRequests()
	return nil
}

func (b *Bing) processRequests() {
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

func (b *Bing) executeQuery(domain string) {
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
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
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
