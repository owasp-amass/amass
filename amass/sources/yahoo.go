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

// Yahoo is the Service that handles access to the Yahoo data source.
type Yahoo struct {
	core.BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewYahoo returns he object initialized, but not yet started.
func NewYahoo(config *core.Config, bus *core.EventBus) *Yahoo {
	y := &Yahoo{
		quantity:   10,
		limit:      100,
		SourceType: core.SCRAPE,
	}

	y.BaseService = *core.NewBaseService(y, "Yahoo", config, bus)
	return y
}

// OnStart implements the Service interface
func (y *Yahoo) OnStart() error {
	y.BaseService.OnStart()

	go y.processRequests()
	return nil
}

func (y *Yahoo) processRequests() {
	for {
		select {
		case <-y.Quit():
			return
		case req := <-y.RequestChan():
			if y.Config().IsDomainInScope(req.Domain) {
				y.executeQuery(req.Domain)
			}
		}
	}
}

func (y *Yahoo) executeQuery(domain string) {
	re := y.Config().DomainRegex(domain)
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
				y.Config().Log.Printf("%s: %s: %v", y.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				y.Bus().Publish(core.NewNameTopic, &core.Request{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    y.SourceType,
					Source: y.String(),
				})
			}
		}
	}
}

func (y *Yahoo) urlByPageNum(domain string, page int) string {
	b := strconv.Itoa(y.quantity*page + 1)
	pz := strconv.Itoa(y.quantity)

	u, _ := url.Parse("https://search.yahoo.com/search")
	u.RawQuery = url.Values{
		"p":     {"site:" + domain + " -domain:www." + domain},
		"b":     {b},
		"pz":    {pz},
		"bct":   {"0"},
		"xargs": {"0"},
	}.Encode()
	return u.String()
}
