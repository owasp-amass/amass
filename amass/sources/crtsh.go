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

const maxCRTConns int = 10

// Crtsh is data source object type that implements the DataSource interface.
type Crtsh struct {
	BaseDataSource
	MaxRequests *utils.Semaphore
}

// NewCrtsh returns an initialized Crtsh as a DataSource.
func NewCrtsh(srv core.AmassService) DataSource {
	c := &Crtsh{
		MaxRequests: utils.NewSemaphore(maxCRTConns),
	}

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
	url := "https://crt.sh/?q=%25." + domain
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		c.Service.Config().Log.Printf("%s: %v", url, err)
		return unique
	}
	c.Service.SetActive()
	// Get the subdomain name the cert was issued to, and
	// the Subject Alternative Name list from each cert
	var idx int
	names := make(chan []string, maxCRTConns)
	results := c.getSubmatches(page)
	t := time.NewTicker(100 * time.Millisecond)
	defer t.Stop()
loop:
	for {
		c.Service.SetActive()

		select {
		case <-c.Service.Quit():
			break loop
		case res := <-names:
			if len(res) > 0 {
				unique = utils.UniqueAppend(unique, res...)
			}
			c.MaxRequests.Release(1)
		case <-t.C:
			if idx >= len(results) {
				if c.MaxRequests.TryAcquire(maxCRTConns) {
					break loop
				}
			} else if c.MaxRequests.TryAcquire(1) {
				go c.getRoutine(results[idx], domain, names)
				idx++
			}
		}
	}
	return unique
}

func (c *Crtsh) getRoutine(id, domain string, names chan []string) {
	url := "https://crt.sh/" + id
	cert, err := utils.GetWebPage(url, nil)
	if err != nil {
		c.Service.Config().Log.Printf("%s: %v", url, err)
		names <- []string{}
		return
	}
	// Get all names off the certificate
	names <- c.getMatches(cert, domain)
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
		results = utils.UniqueAppend(results, strings.TrimSpace(subs[1]))
	}
	return results
}
