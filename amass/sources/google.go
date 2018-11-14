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

// Google is data source object type that implements the DataSource interface.
type Google struct {
	BaseDataSource
	quantity int
	limit    int
}

// NewGoogle returns an initialized Google as a DataSource.
func NewGoogle(srv core.AmassService) DataSource {
	g := &Google{
		quantity: 10,
		limit:    100,
	}

	g.BaseDataSource = *NewBaseDataSource(srv, core.SCRAPE, "Google")
	return g
}

// Query returns the subdomain names discovered when querying this data source.
func (g *Google) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(sub)
	num := g.limit / g.quantity
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for i := 0; i < num; i++ {
		g.Service.SetActive()

		select {
		case <-g.Service.Quit():
			break loop
		case <-t.C:
			u := g.urlByPageNum(sub, i)
			page, err := utils.RequestWebPage(u, nil, nil, "", "")
			if err != nil {
				g.Service.Config().Log.Printf("%s: %v", u, err)
				break
			}

			for _, sd := range re.FindAllString(page, -1) {
				if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
					unique = append(unique, u...)
				}
			}
		}
	}
	return unique
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
