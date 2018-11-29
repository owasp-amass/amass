// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net/url"
	"strconv"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Google is the Service that handles access to the Google search engine data source.
type Google struct {
	BaseService

	quantity   int
	limit      int
	SourceType string
}

// NewGoogle returns he object initialized, but not yet started.
func NewGoogle(e *Enumeration) *Google {
	g := &Google{
		quantity:   10,
		limit:      100,
		SourceType: SCRAPE,
	}

	g.BaseService = *NewBaseService(e, "Google", g)
	return g
}

// OnStart implements the Service interface
func (g *Google) OnStart() error {
	g.BaseService.OnStart()

	go g.startRootDomains()
	go g.processRequests()
	return nil
}

func (g *Google) processRequests() {
	for {
		select {
		case <-g.PauseChan():
			<-g.ResumeChan()
		case <-g.Quit():
			return
		case <-g.RequestChan():
			// This data source just throws away the checked DNS names
			g.SetActive()
		}
	}
}

func (g *Google) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range g.Enum().Config.Domains() {
		g.executeQuery(domain)
	}
}

func (g *Google) executeQuery(domain string) {
	re := g.Enum().Config.DomainRegex(domain)
	num := g.limit / g.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for i := 0; i < num; i++ {
		g.SetActive()

		select {
		case <-g.Quit():
			return
		case <-t.C:
			u := g.urlByPageNum(domain, i)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				g.Enum().Log.Printf("%s: %s: %v", g.String(), u, err)
				return
			}

			for _, sd := range re.FindAllString(page, -1) {
				g.Enum().NewNameEvent(&Request{
					Name:   cleanName(sd),
					Domain: domain,
					Tag:    g.SourceType,
					Source: g.String(),
				})
			}
		}
	}
}

func (g *Google) urlByPageNum(domain string, page int) string {
	start := strconv.Itoa(g.quantity * page)
	u, _ := url.Parse("https://www.google.com/search")

	u.RawQuery = url.Values{
		"q":      {"site:" + domain},
		"btnG":   {"Search"},
		"hl":     {"en"},
		"biw":    {""},
		"bih":    {""},
		"gbv":    {"1"},
		"start":  {start},
		"filter": {"0"},
	}.Encode()
	return u.String()
}
