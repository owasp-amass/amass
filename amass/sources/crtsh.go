// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

type Crtsh struct {
	BaseDataSource
}

func NewCrtsh(srv core.AmassService) DataSource {
	c := new(Crtsh)

	c.BaseDataSource = *NewBaseDataSource(srv, CERT, "crt.sh")
	return c
}

func (c *Crtsh) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	// Pull the page that lists all certs for this domain
	url := "https://crt.sh/?q=%25." + domain
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		c.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	c.Service.SetActive()
	// Get the subdomain name the cert was issued to, and
	// the Subject Alternative Name list from each cert
	results := c.getSubmatches(page)
	t := time.NewTicker(50 * time.Millisecond)
	defer t.Stop()
loop:
	for _, rel := range results {
		c.Service.SetActive()

		select {
		case <-c.Service.Quit():
			break loop
		case <-t.C:
			url = "https://crt.sh/" + rel
			cert, err := utils.GetWebPage(url, nil)
			if err != nil {
				c.Service.Config().Log.Printf("%s: %v", url, err)
				continue
			}
			// Get all names off the certificate
			unique = utils.UniqueAppend(unique, c.getMatches(cert, domain)...)
		}
	}
	return unique
}

func (c *Crtsh) getMatches(content, domain string) []string {
	var results []string

	re := utils.SubdomainRegex(domain)
	for _, s := range re.FindAllString(content, -1) {
		results = append(results, s)
	}
	return results
}

func (c *Crtsh) getSubmatches(content string) []string {
	var results []string

	re := regexp.MustCompile("<TD style=\"text-align:center\"><A href=\"([?]id=[a-zA-Z0-9]*)\">[a-zA-Z0-9]*</A></TD>")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		results = append(results, strings.TrimSpace(subs[1]))
	}
	return results
}
