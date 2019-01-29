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

// Baidu is the Service that handles access to the Baidu data source.
type Baidu struct {
	core.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewBaidu returns he object initialized, but not yet started.
func NewBaidu(config *core.Config, bus *core.EventBus) *Baidu {
	b := &Baidu{
		quantity:   20,
		limit:      100,
		SourceType: core.SCRAPE,
	}

	b.BaseService = *core.NewBaseService(b, "Baidu", config, bus)
	return b
}

// OnStart implements the Service interface
func (b *Baidu) OnStart() error {
	b.BaseService.OnStart()

	go b.startRootDomains()
	return nil
}

func (b *Baidu) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range b.Config().Domains() {
		b.executeQuery(domain)
	}
}

func (b *Baidu) executeQuery(domain string) {
	re := b.Config().DomainRegex(domain)
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
				b.Config().Log.Printf("%s: %s: %v", b.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				b.Bus().Publish(core.NewNameTopic, &core.Request{
					Name:   cleanName(sd),
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
	query := "site:" + domain + " -site:www." + domain

	u.RawQuery = url.Values{
		"pn": {pn},
		"wd": {query},
		"oq": {query},
	}.Encode()
	return u.String()
}
