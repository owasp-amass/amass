// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
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

// Yahoo is the Service that handles access to the Yahoo data source.
type Yahoo struct {
	services.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewYahoo returns he object initialized, but not yet started.
func NewYahoo(c *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Yahoo {
	y := &Yahoo{
		quantity:   10,
		limit:      100,
		SourceType: requests.SCRAPE,
	}

	y.BaseService = *services.NewBaseService(y, "Yahoo", c, bus, pool)
	return y
}

// OnStart implements the Service interface
func (y *Yahoo) OnStart() error {
	y.BaseService.OnStart()

	go y.processRequests()
	return nil
}

func (y *Yahoo) processRequests() {
	for {
		select {
		case <-y.Quit():
			return
		case req := <-y.DNSRequestChan():
			if y.Config().IsDomainInScope(req.Domain) {
				y.executeQuery(req.Domain)
			}
		case <-y.AddrRequestChan():
		case <-y.ASNRequestChan():
		case <-y.WhoisRequestChan():
		}
	}
}

func (y *Yahoo) executeQuery(domain string) {
	re := y.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	num := y.limit / y.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for i := 0; i < num; i++ {
		y.SetActive()

		select {
		case <-y.Quit():
			return
		case <-t.C:
			u := y.urlByPageNum(domain, i)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				y.Config().Log.Printf("%s: %s: %v", y.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				y.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   cleanName(sd),
					Domain: domain,
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
