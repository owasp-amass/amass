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

// Bing is the Service that handles access to the Bing data source.
type Bing struct {
	core.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewBing returns he object initialized, but not yet started.
func NewBing(config *core.Config, bus *core.EventBus) *Bing {
	b := &Bing{
		quantity:   20,
		limit:      200,
		SourceType: core.SCRAPE,
	}

	b.BaseService = *core.NewBaseService(b, "Bing", config, bus)
	return b
}

// OnStart implements the Service interface
func (b *Bing) OnStart() error {
	b.BaseService.OnStart()

	go b.processRequests()
	return nil
}

func (b *Bing) processRequests() {
	for {
		select {
		case <-b.Quit():
			return
		case req := <-b.RequestChan():
			if b.Config().IsDomainInScope(req.Domain) {
				b.executeQuery(req.Domain)
			}
		}
	}
}

func (b *Bing) executeQuery(domain string) {
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

func (b *Bing) urlByPageNum(domain string, page int) string {
	count := strconv.Itoa(b.quantity)
	first := strconv.Itoa((page * b.quantity) + 1)
	u, _ := url.Parse("http://www.bing.com/search")

	u.RawQuery = url.Values{
		"q":     {"domain:" + domain + " -www." + domain},
		"count": {count},
		"first": {first},
		"FORM":  {"PORE"},
	}.Encode()
	return u.String()
}
