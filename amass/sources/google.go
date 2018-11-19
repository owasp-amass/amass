// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
)

// Google is the AmassService that handles access to the Google search engine data source.
type Google struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	quantity   int
	limit      int
	SourceType string
	filter     *utils.StringFilter
}

// NewGoogle requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewGoogle(bus evbus.Bus, config *core.AmassConfig) *Google {
	g := &Google{
		Bus:        bus,
		Config:     config,
		quantity:   10,
		limit:      100,
		SourceType: core.SCRAPE,
		filter:     utils.NewStringFilter(),
	}

	g.BaseAmassService = *core.NewBaseAmassService("Google", g)
	return g
}

// OnStart implements the AmassService interface
func (g *Google) OnStart() error {
	g.BaseAmassService.OnStart()

	go g.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (g *Google) OnStop() error {
	g.BaseAmassService.OnStop()
	return nil
}

func (g *Google) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range g.Config.Domains() {
		g.executeQuery(domain)
	}
}

func (g *Google) executeQuery(domain string) {
	re := g.Config.DomainRegex(domain)
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
				g.Config.Log.Printf("%s: %s: %v", g.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				n := cleanName(sd)

				if g.filter.Duplicate(n) {
					continue
				}
				go func(name string) {
					g.Config.MaxFlow.Acquire(1)
					g.Bus.Publish(core.NEWNAME, &core.AmassRequest{
						Name:   name,
						Domain: domain,
						Tag:    g.SourceType,
						Source: g.String(),
					})
				}(n)
			}
		}
	}
}

func (g *Google) urlByPageNum(domain string, page int) string {
	start := strconv.Itoa(g.quantity * page)
	u, _ := url.Parse("https://www.google.com/search")

	u.RawQuery = url.Values{
		"q":      {"site:" + domain},
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
