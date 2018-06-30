// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/caffix/amass/amass/internal/utils"
)

type CertDB struct {
	BaseDataSource
}

func NewCertDB() DataSource {
	c := new(CertDB)

	c.BaseDataSource = *NewBaseDataSource(CERT, "CertDB")
	return c
}

func (c *CertDB) Query(domain, sub string) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	// Pull the page that lists all certs for this domain
	url := "https://certdb.com/domain/" + domain
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		c.Log(fmt.Sprintf("%s: %v", url, err))
		return unique
	}
	// Get the subdomain name the cert was issued to, and
	// the Subject Alternative Name list from each cert
	for _, rel := range c.getSubmatches(page) {
		// Do not go too fast
		time.Sleep(50 * time.Millisecond)
		// Pull the certificate web page
		url = "https://certdb.com" + rel
		cert, err := utils.GetWebPage(url, nil)
		if err != nil {
			c.Log(fmt.Sprintf("%s: %v", url, err))
			continue
		}
		// Get all names off the certificate
		unique = utils.UniqueAppend(unique, c.getMatches(cert, domain)...)
	}
	return unique
}

func (c *CertDB) getMatches(content, domain string) []string {
	var results []string

	re := utils.SubdomainRegex(domain)
	for _, s := range re.FindAllString(content, -1) {
		results = append(results, s)
	}
	return results
}

func (c *CertDB) getSubmatches(content string) []string {
	var results []string

	re := regexp.MustCompile("href=\"(/ssl-cert/[a-zA-Z0-9]*)\"")
	for _, subs := range re.FindAllStringSubmatch(content, -1) {
		results = append(results, strings.TrimSpace(subs[1]))
	}
	return results
}
