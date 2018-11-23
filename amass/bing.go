// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Bing is the AmassService that handles access to the Bing data source.
type Bing struct {
	BaseAmassService

	quantity   int
	limit      int
	SourceType string
}

// NewBing returns he object initialized, but not yet started.
func NewBing(e *Enumeration) *Bing {
	b := &Bing{
		quantity:   20,
		limit:      200,
		SourceType: SCRAPE,
	}

	b.BaseAmassService = *NewBaseAmassService(e, "Bing", b)
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
	for _, domain := range b.Enum().Config.Domains() {
		b.executeQuery(domain)
	}
}

func (b *Bing) executeQuery(domain string) {
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
				b.Enum().NewNameEvent(&AmassRequest{
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

	u.RawQuery = url.Values{"q": {"domain:" + domain},
		"count": {count}, "first": {first}, "FORM": {"PORE"}}.Encode()
	return u.String()
}
