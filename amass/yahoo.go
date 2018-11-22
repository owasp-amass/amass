// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Yahoo is the AmassService that handles access to the Yahoo data source.
type Yahoo struct {
	BaseAmassService

	quantity   int
	limit      int
	SourceType string
}

// NewYahoo returns he object initialized, but not yet started.
func NewYahoo(e *Enumeration) *Yahoo {
	y := &Yahoo{
		quantity:   10,
		limit:      100,
		SourceType: SCRAPE,
	}

	y.BaseAmassService = *NewBaseAmassService(e, "Yahoo", y)
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
	for _, domain := range y.Enum().Config.Domains() {
		y.executeQuery(domain)
	}
}

func (y *Yahoo) executeQuery(domain string) {
	re := y.Enum().Config.DomainRegex(domain)
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
				y.Enum().Log.Printf("%s: %s: %v", y.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				req := &AmassRequest{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    y.SourceType,
					Source: y.String(),
				}

				if y.Enum().DupDataSourceName(req) {
					continue
				}
				y.Enum().Bus.Publish(NEWNAME, req)
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
