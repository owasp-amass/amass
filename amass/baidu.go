// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Baidu is the AmassService that handles access to the Baidu data source.
type Baidu struct {
	BaseAmassService

	quantity   int
	limit      int
	SourceType string
}

// NewBaidu returns he object initialized, but not yet started.
func NewBaidu(e *Enumeration) *Baidu {
	b := &Baidu{
		quantity:   20,
		limit:      100,
		SourceType: SCRAPE,
	}

	b.BaseAmassService = *NewBaseAmassService(e, "Baidu", b)
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
	for _, domain := range b.Enum().Config.Domains() {
		b.executeQuery(domain)
	}
}

func (b *Baidu) executeQuery(domain string) {
	re := b.Enum().Config.DomainRegex(domain)
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
				b.Enum().Log.Printf("%s: %s: %v", b.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				req := &AmassRequest{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    b.SourceType,
					Source: b.String(),
				}

				if b.Enum().DupDataSourceName(req) {
					continue
				}
				b.Enum().Bus.Publish(NEWNAME, req)
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
