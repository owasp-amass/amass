// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/caffix/amass/amass/internal/utils"
)

type HackerTarget struct {
	BaseDataSource
}

func NewHackerTarget() DataSource {
	h := new(HackerTarget)

	h.BaseDataSource = *NewBaseDataSource(SCRAPE, "HackerTarget")
	return h
}

func (h *HackerTarget) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := h.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		h.log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}

	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (h *HackerTarget) getURL(domain string) string {
	format := "http://api.hackertarget.com/hostsearch/?q=%s"

	return fmt.Sprintf(format, domain)
}
