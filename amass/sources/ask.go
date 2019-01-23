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

// Ask is the Service that handles access to the Ask data source.
type Ask struct {
	core.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewAsk returns he object initialized, but not yet started.
func NewAsk(config *core.Config, bus *core.EventBus) *Ask {
	a := &Ask{
		quantity:   10, // ask.com appears to be hardcoded at 10 results per page
		limit:      100,
		SourceType: core.SCRAPE,
	}

	a.BaseService = *core.NewBaseService(a, "Ask", config, bus)
	return a
}

// OnStart implements the Service interface
func (a *Ask) OnStart() error {
	a.BaseService.OnStart()

	go a.startRootDomains()
	return nil
}

func (a *Ask) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range a.Config().Domains() {
		a.executeQuery(domain)
	}
}

func (a *Ask) executeQuery(domain string) {
	re := a.Config().DomainRegex(domain)
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
				a.Config().Log.Printf("%s: %s: %v", a.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				a.Bus().Publish(core.NewNameTopic, &core.Request{
					Name:   cleanName(sd),
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

	u.RawQuery = url.Values{
		"q":    {"site:" + domain + " -www." + domain},
		"o":    {"0"},
		"l":    {"dir"},
		"qo":   {"pagination"},
		"page": {p},
	}.Encode()
	return u.String()
}
