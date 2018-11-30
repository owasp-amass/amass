// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Dogpile is the Service that handles access to the Dogpile data source.
type Dogpile struct {
	BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewDogpile returns he object initialized, but not yet started.
func NewDogpile(e *Enumeration) *Dogpile {
	d := &Dogpile{
		quantity:   15, // Dogpile returns roughly 15 results per page
		limit:      90,
		SourceType: SCRAPE,
	}

	d.BaseService = *NewBaseService(e, "Dogpile", d)
	return d
}

// OnStart implements the Service interface
func (d *Dogpile) OnStart() error {
	d.BaseService.OnStart()

	go d.startRootDomains()
	go d.processRequests()
	return nil
}

func (d *Dogpile) processRequests() {
	for {
		select {
		case <-d.PauseChan():
			<-d.ResumeChan()
		case <-d.Quit():
			return
		case <-d.RequestChan():
			// This data source just throws away the checked DNS names
			d.SetActive()
		}
	}
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
				d.Enum().NewNameEvent(&Request{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    d.SourceType,
					Source: d.String(),
				})
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
