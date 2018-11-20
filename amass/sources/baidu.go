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

// Baidu is the AmassService that handles access to the Baidu data source.
type Baidu struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	quantity   int
	limit      int
	SourceType string
}

// NewBaidu requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewBaidu(bus evbus.Bus, config *core.AmassConfig) *Baidu {
	b := &Baidu{
		Bus:        bus,
		Config:     config,
		quantity:   20,
		limit:      100,
		SourceType: core.SCRAPE,
	}

	b.BaseAmassService = *core.NewBaseAmassService("Baidu", b)
	return b
}

// OnStart implements the AmassService interface
func (b *Baidu) OnStart() error {
	b.BaseAmassService.OnStart()

	go b.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (b *Baidu) OnStop() error {
	b.BaseAmassService.OnStop()
	return nil
}

func (b *Baidu) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range b.Config.Domains() {
		b.executeQuery(domain)
	}
}

func (b *Baidu) executeQuery(domain string) {
	re := b.Config.DomainRegex(domain)
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
				b.Config.Log.Printf("%s: %s: %v", b.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				n := cleanName(sd)

				if core.DataSourceNameFilter.Duplicate(n) {
					continue
				}

				b.Bus.Publish(core.NEWNAME, &core.AmassRequest{
					Name:   n,
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

	u.RawQuery = url.Values{"pn": {pn}, "wd": {domain}, "oq": {domain}}.Encode()
	return u.String()
}
