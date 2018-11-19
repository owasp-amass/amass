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

// Bing is the AmassService that handles access to the Bing data source.
type Bing struct {
	core.BaseAmassService

	Bus        evbus.Bus
	Config     *core.AmassConfig
	quantity   int
	limit      int
	SourceType string
	filter     *utils.StringFilter
}

// NewBing requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewBing(config *core.AmassConfig, bus evbus.Bus) *Bing {
	b := &Bing{
		Bus:        bus,
		Config:     config,
		quantity:   20,
		limit:      200,
		SourceType: core.SCRAPE,
		filter:     utils.NewStringFilter(),
	}

	b.BaseAmassService = *core.NewBaseAmassService("Bing", b)
	return b
}

// OnStart implements the AmassService interface
func (b *Bing) OnStart() error {
	b.BaseAmassService.OnStart()

	go b.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (b *Bing) OnStop() error {
	b.BaseAmassService.OnStop()
	return nil
}

func (b *Bing) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range b.Config.Domains() {
		b.executeQuery(domain)
	}
}

func (b *Bing) executeQuery(domain string) {
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

				if b.filter.Duplicate(n) {
					continue
				}
				go func(name string) {
					b.Config.MaxFlow.Acquire(1)
					b.Bus.Publish(core.NEWNAME, &core.AmassRequest{
						Name:   name,
						Domain: domain,
						Tag:    b.SourceType,
						Source: b.String(),
					})
				}(n)
			}
		}
	}
}

func (b *Bing) urlByPageNum(domain string, page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{"q": {"domain:" + domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}
