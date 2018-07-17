// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"net/url"

	"github.com/OWASP/Amass/amass/internal/utils"
)

type CertDB struct {
	BaseDataSource
}

func NewCertDB() DataSource {
	c := new(CertDB)

	c.BaseDataSource = *NewBaseDataSource(API, "CertDB")
	return c
}

func (c *CertDB) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	u := c.getURL(domain)
	page, err := utils.GetWebPage(u, nil)
	if err != nil {
		c.log(fmt.Sprintf("%s: %v", u, err))
		return unique
	}

	var names []string
	if err := json.Unmarshal([]byte(page), &names); err != nil {
		c.log(fmt.Sprintf("Failed to unmarshal JSON: %v", err))
		return unique
	}

	re := utils.SubdomainRegex(domain)
	for _, name := range names {
		if n := re.FindString(name); n != "" {
			unique = utils.UniqueAppend(unique, n)
		}
	}
	return unique
}

func (c *CertDB) getURL(domain string) string {
	u, _ := url.Parse("https://certdb.com/api")

	u.RawQuery = url.Values{
		"q":             {domain},
		"response_type": {"3"},
	}.Encode()
	return u.String()
}
