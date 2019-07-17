// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"net/url"
	"time"

	"github.com/OWASP/Amass/amass/core"
	eb "github.com/OWASP/Amass/amass/eventbus"
	"github.com/OWASP/Amass/amass/utils"
)

// CertSpotter is the Service that handles access to the CertSpotter data source.
type CertSpotter struct {
	core.BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewCertSpotter returns he object initialized, but not yet started.
func NewCertSpotter(config *core.Config, bus *eb.EventBus) *CertSpotter {
	c := &CertSpotter{
		SourceType: core.CERT,
		RateLimit:  2 * time.Second,
	}

	c.BaseService = *core.NewBaseService(c, "CertSpotter", config, bus)
	return c
}

// OnStart implements the Service interface
func (c *CertSpotter) OnStart() error {
	c.BaseService.OnStart()

	go c.processRequests()
	return nil
}

func (c *CertSpotter) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)

	for {
		select {
		case <-c.Quit():
			return
		case req := <-c.DNSRequestChan():
			if c.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < c.RateLimit {
					time.Sleep(c.RateLimit)
				}
				last = time.Now()
				c.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-c.AddrRequestChan():
		case <-c.ASNRequestChan():
		case <-c.WhoisRequestChan():
		}
	}
}

func (c *CertSpotter) executeQuery(domain string) {
	re := c.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	c.SetActive()
	url := c.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		c.Config().Log.Printf("%s: %s: %v", c.String(), url, err)
		return
	}
	// Extract the subdomain names from the certificate information
	var m []struct {
		Names []string `json:"dns_names"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		return
	}

	for _, result := range m {
		for _, name := range result.Names {
			if re.MatchString(name) {
				c.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
					Name:   utils.RemoveAsteriskLabel(name),
					Domain: domain,
					Tag:    c.SourceType,
					Source: c.String(),
				})
			}
		}
	}
}

func (c *CertSpotter) getURL(domain string) string {
	u, _ := url.Parse("https://api.certspotter.com/v1/issuances")

	u.RawQuery = url.Values{
		"domain":             {domain},
		"include_subdomains": {"true"},
		"match_wildcards":    {"true"},
		"expand":             {"dns_names"},
	}.Encode()
	return u.String()
}
