// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"io"
	"strings"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// Crtsh is data source object type that implements the DataSource interface.
type Crtsh struct {
	BaseDataSource
}

type crtData struct {
	IssuerID          int    `json:"issuer_ca_id"`
	IssuerName        string `json:"issuer_name"`
	Name              string `json:"name_value"`
	MinCertID         int    `json:"min_cert_id"`
	MinEntryTimestamp string `json:"min_entry_timestamp"`
	NotBefore         string `json:"not_before"`
	NotAfter          string `json:"not_after"`
}

// NewCrtsh returns an initialized Crtsh as a DataSource.
func NewCrtsh(srv core.AmassService) DataSource {
	c := new(Crtsh)

	c.BaseDataSource = *NewBaseDataSource(srv, core.CERT, "crt.sh")
	return c
}

// Query returns the subdomain names discovered when querying this data source.
func (c *Crtsh) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}
	// Pull the page that lists all certs for this domain
	url := c.getURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		c.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	c.Service.SetActive()

	lines := json.NewDecoder(strings.NewReader(page))
	for {
		var line crtData
		if err := lines.Decode(&line); err == io.EOF {
			break
		} else if err != nil {
			c.Service.Config().Log.Printf("%s: %v", url, err)
		}
		unique = utils.UniqueAppend(unique, line.Name)
	}
	return unique
}

func (c *Crtsh) getURL(domain string) string {
	return "https://crt.sh/?q=%25." + domain + "&output=json"
}
