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

// Dogpile is the AmassService that handles access to the Dogpile data source.
type Dogpile struct {
	core.BaseAmassService

	quantity   int
	limit      int
	SourceType string
}

// NewDogpile returns he object initialized, but not yet started.
func NewDogpile(e *core.Enumeration) *Dogpile {
	d := &Dogpile{
		quantity:   15, // Dogpile returns roughly 15 results per page
		limit:      90,
		SourceType: core.SCRAPE,
	}

	d.BaseAmassService = *core.NewBaseAmassService(e, "Dogpile", d)
	return d
}

// OnStart implements the AmassService interface
func (d *Dogpile) OnStart() error {
	d.BaseAmassService.OnStart()

	go d.startRootDomains()
	return nil
}

// OnStop implements the AmassService interface
func (d *Dogpile) OnStop() error {
	d.BaseAmassService.OnStop()
	return nil
}

func (d *Dogpile) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range d.Enum().Config.Domains() {
		d.executeQuery(domain)
	}
}

func (d *Dogpile) executeQuery(domain string) {
	re := d.Enum().Config.DomainRegex(domain)
	num := d.limit / d.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for i := 0; i < num; i++ {
		d.SetActive()

		select {
		case <-d.Quit():
			return
		case <-t.C:
			u := d.urlByPageNum(domain, i)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				d.Enum().Log.Printf("%s: %s: %v", d.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				req := &core.AmassRequest{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    d.SourceType,
					Source: d.String(),
				}

				if d.Enum().DupDataSourceName(req) {
					continue
				}
				d.Enum().Bus.Publish(core.NEWNAME, req)
			}
		}
	}
}

func (d *Dogpile) urlByPageNum(domain string, page int) string {
	qsi := strconv.Itoa(d.quantity * page)
	u, _ := url.Parse("http://www.dogpile.com/search/web")

	u.RawQuery = url.Values{"qsi": {qsi}, "q": {domain}}.Encode()
	return u.String()
}
