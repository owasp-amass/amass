// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// HackerTarget is data source object type that implements the DataSource interface.
type HackerTarget struct {
	BaseDataSource
}

// NewHackerTarget returns an initialized HackerTarget as a DataSource.
func NewHackerTarget(srv core.AmassService) DataSource {
	h := new(HackerTarget)

	h.BaseDataSource = *NewBaseDataSource(srv, core.API, "HackerTarget")
	return h
}

// Query returns the subdomain names discovered when querying this data source.
func (h *HackerTarget) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	url := h.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		h.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	h.Service.SetActive()

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
