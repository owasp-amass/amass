// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"net/url"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// CertDB is data source object type that implements the DataSource interface.
type CertDB struct {
	BaseDataSource
}

// NewCertDB returns an initialized CertDB as a DataSource.
func NewCertDB(srv core.AmassService) DataSource {
	c := new(CertDB)

	c.BaseDataSource = *NewBaseDataSource(srv, core.CERT, "CertDB")
	return c
}

// Query returns the subdomain names discovered when querying this data source.
func (c *CertDB) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	u := c.getURL(domain)
	page, err := utils.GetWebPage(u, nil)
	if err != nil {
		c.Service.Config().Log.Printf("%s: %v", u, err)
		return unique
	}

	c.Service.SetActive()
	var names []string
	if err := json.Unmarshal([]byte(page), &names); err != nil {
		c.Service.Config().Log.Printf("Failed to unmarshal JSON: %v", err)
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
