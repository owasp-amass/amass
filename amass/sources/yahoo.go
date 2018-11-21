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

// Yahoo is the AmassService that handles access to the Yahoo data source.
type Yahoo struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	quantity   int
	limit      int
	SourceType string
}

// NewYahoo requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewYahoo(e *core.Enumeration, bus evbus.Bus, config *core.AmassConfig) *Yahoo {
	y := &Yahoo{
		Bus:        bus,
		Config:     config,
		quantity:   10,
		limit:      100,
		SourceType: core.SCRAPE,
	}

	y.BaseAmassService = *core.NewBaseAmassService(e, "Yahoo", y)
	return y
}

// OnStart implements the AmassService interface
func (y *Yahoo) OnStart() error {
	y.BaseAmassService.OnStart()

	go y.startRootDomains()
	return nil
}

func (y *Yahoo) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range y.Config.Domains() {
		y.executeQuery(domain)
	}
}

func (y *Yahoo) executeQuery(domain string) {
	re := y.Config.DomainRegex(domain)
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
				y.Config.Log.Printf("%s: %s: %v", y.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				req := &core.AmassRequest{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    y.SourceType,
					Source: y.String(),
				}

				if y.Enum().DupDataSourceName(req) {
					continue
				}
				y.Bus.Publish(core.NEWNAME, req)
			}
		}
	}
}

func (y *Yahoo) urlByPageNum(domain string, page int) string {
	b := strconv.Itoa(y.quantity*page + 1)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("https://search.yahoo.com/search")
	u.RawQuery = url.Values{"p": {"site:" + domain},
		"b": {b}, "pz": {pz}, "bct": {"0"}, "xargs": {"0"}}.Encode()
	return u.String()
}
