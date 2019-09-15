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

// Google is the Service that handles access to the Google search engine data source.
type Google struct {
	services.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewGoogle returns he object initialized, but not yet started.
func NewGoogle(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Google {
	g := &Google{
		quantity:   10,
		limit:      100,
		SourceType: requests.SCRAPE,
	}

	g.BaseService = *services.NewBaseService(g, "Google", cfg, bus, pool)
	return g
}

// OnStart implements the Service interface
func (g *Google) OnStart() error {
	g.BaseService.OnStart()

	go g.processRequests()
	return nil
}

func (g *Google) processRequests() {
	for {
		select {
		case <-g.Quit():
			return
		case req := <-g.DNSRequestChan():
			if g.Config().IsDomainInScope(req.Domain) {
				for i := 0; i <= 3; i++ {
					g.executeQuery(req.Domain, i)
				}

			}
		case <-g.AddrRequestChan():
		case <-g.ASNRequestChan():
		case <-g.WhoisRequestChan():
		}
	}
}

func (g *Google) executeQuery(domain string, numwilds int) {
	re := g.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	num := g.limit / g.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for i := 0; i < num; i++ {
		g.SetActive()

		select {
		case <-g.Quit():
			return
		case <-t.C:
			u := g.urlByPageNum(domain, i, numwilds)
			page, err := http.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				g.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", g.String(), u, err))
				return
			}

			for _, name := range re.FindAllString(page, -1) {
				g.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
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
