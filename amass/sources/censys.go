// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Censys is data source object type that implements the DataSource interface.
type Censys struct {
	BaseDataSource
}

// NewCensys returns an initialized Censys as a DataSource.
func NewCensys(srv core.AmassService) DataSource {
	c := new(Censys)

	c.BaseDataSource = *NewBaseDataSource(srv, core.CERT, "Censys")
	return c
}

// Query returns the subdomain names discovered when querying this data source.
func (c *Censys) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return []string{}
	}

	var err error
	var url, page, uid, secret string
	if key := c.Service.Config().GetAPIKey(c.Name); key != "" {
		url = c.restURL()

		jsonStr, err := json.Marshal(map[string]string{"query": sub})
		if err != nil {
			return unique
		}
		body := bytes.NewBuffer(jsonStr)
		headers := map[string]string{"Content-Type": "application/json"}
		page, err = utils.RequestWebPage(url, body, headers, uid, secret)
	} else {
		url = c.webURL(sub)

		page, err = utils.RequestWebPage(url, nil, nil, "", "")
	}

	if err != nil {
		c.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}

	c.Service.SetActive()
	re := utils.SubdomainRegex(domain)
	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func (c *Censys) webURL(domain string) string {
	return fmt.Sprintf("https://www.censys.io/domain/%s/table", domain)
}

func (c *Censys) restURL() string {
	return "https://www.censys.io/api/v1/search/certificates"
}

// APIKeyRequired serves as a default implementation of the DataSource interface.
func (c *Censys) APIKeyRequired() int {
	return APIkeyOptional
}
