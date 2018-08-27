// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

type Google struct {
	sync.Mutex
	BaseDataSource
	quantity int
	limit    int
}

func NewGoogle() DataSource {
	g := &Google{
		quantity: 10,
		limit:    100,
	}

	g.BaseDataSource = *NewBaseDataSource(SCRAPE, "Google")
	return g
}

func (g *Google) Query(domain, sub string) []string {
	g.Lock()
	defer g.Unlock()

	var unique []string

	re := utils.SubdomainRegex(sub)
	num := g.limit / g.quantity
	for i := 0; i < num; i++ {
		u := g.urlByPageNum(sub, i)
		page, err := utils.GetWebPage(u, nil)
		if err != nil {
			g.log(fmt.Sprintf("%s: %v", u, err))
			break
		}

		for _, sd := range re.FindAllString(page, -1) {
			if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
				unique = append(unique, u...)
			}
		}
		time.Sleep(1 * time.Second)
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

func (g *Google) Subdomains() bool {
	return true
}
