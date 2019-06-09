// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Google is the Service that handles access to the Google search engine data source.
type Google struct {
	core.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewGoogle returns he object initialized, but not yet started.
func NewGoogle(config *core.Config, bus *core.EventBus) *Google {
	g := &Google{
		quantity:   10,
		limit:      100,
		SourceType: core.SCRAPE,
	}

	g.BaseService = *core.NewBaseService(g, "Google", config, bus)
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
				g.executeQuery(req.Domain)
			}
		case <-g.AddrRequestChan():
		case <-g.ASNRequestChan():
		case <-g.WhoisRequestChan():
		}
	}
}

func (g *Google) executeQuery(domain string) {
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
			u := g.urlByPageNum(domain, i)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				g.Config().Log.Printf("%s: %s: %v", g.String(), u, err)
				return
			}

			for _, name := range re.FindAllString(page, -1) {
				g.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
					Name:   cleanName(name),
					Domain: domain,
					Tag:    g.SourceType,
					Source: g.String(),
				})
			}
		}
	}
}

func (g *Google) urlByPageNum(domain string, page int) string {
	start := strconv.Itoa(g.quantity * page)
	u, _ := url.Parse("https://www.google.com/search")

	u.RawQuery = url.Values{
		"q":      {"site:" + domain + " -www." + domain},
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
