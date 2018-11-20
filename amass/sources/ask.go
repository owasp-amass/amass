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

// Ask is the AmassService that handles access to the Ask data source.
type Ask struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	quantity   int
	limit      int
	SourceType string
}

// NewAsk requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewAsk(bus evbus.Bus, config *core.AmassConfig) *Ask {
	a := &Ask{
		Bus:        bus,
		Config:     config,
		quantity:   10, // ask.com appears to be hardcoded at 10 results per page
		limit:      100,
		SourceType: core.SCRAPE,
	}

	a.BaseAmassService = *core.NewBaseAmassService("Ask", a)
	return a
}

// OnStart implements the AmassService interface
func (a *Ask) OnStart() error {
	a.BaseAmassService.OnStart()

	go a.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (a *Ask) OnStop() error {
	a.BaseAmassService.OnStop()
	return nil
}

func (a *Ask) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range a.Config.Domains() {
		a.executeQuery(domain)
	}
}

func (a *Ask) executeQuery(domain string) {
	re := a.Config.DomainRegex(domain)
	num := a.limit / a.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for i := 0; i < num; i++ {
		a.SetActive()

		select {
		case <-a.Quit():
			return
		case <-t.C:
			u := a.urlByPageNum(domain, i)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				a.Config.Log.Printf("%s: %s: %v", a.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				n := cleanName(sd)

				if core.DataSourceNameFilter.Duplicate(n) {
					continue
				}

				a.Bus.Publish(core.NEWNAME, &core.AmassRequest{
					Name:   n,
					Domain: domain,
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

	u.RawQuery = url.Values{"q": {"site:" + domain},
		"o": {"0"}, "l": {"dir"}, "qo": {"pagination"}, "page": {p}}.Encode()
	return u.String()
}
