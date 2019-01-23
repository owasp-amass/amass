// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// CertDB is the Service that handles access to the CertDB data source.
type CertDB struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
}

// NewCertDB returns he object initialized, but not yet started.
func NewCertDB(config *core.Config, bus *core.EventBus) *CertDB {
	c := &CertDB{SourceType: core.API}

	c.BaseService = *core.NewBaseService(c, "CertDB", config, bus)
	return c
}

// OnStart implements the Service interface
func (c *CertDB) OnStart() error {
	c.BaseService.OnStart()

	c.API = c.Config().GetAPIKey(c.String())
	if c.API == nil || c.API.Username == "" || c.API.Password == "" {
		c.Config().Log.Printf("%s: API key data was not provided", c.String())
	} else {
		c.authenticate()
	}

	go c.startRootDomains()
	return nil
}

func (c *CertDB) startRootDomains() {
	// Look at each domain provided by the config
	for _, domain := range c.Config().Domains() {
		c.executeQuery(domain)
	}
}

func (c *CertDB) executeQuery(domain string) {
	if !utils.CheckCookie("http://certdb.com", "user_token") {
		return
	}

	u := c.getURL(domain)
	page, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		c.Config().Log.Printf("%s: %s: %v", c.String(), u, err)
		return
	}

	var results []struct {
		Domains []struct {
			Domain string `json:"domain"`
		}
	}

	if err := json.Unmarshal([]byte(page), &results); err != nil {
		c.Config().Log.Printf("%s: Failed to unmarshal JSON: %v", c.String(), err)
		return
	}

	c.SetActive()
	re := c.Config().DomainRegex(domain)
	for _, domains := range results {
		for _, name := range domains.Domains {
			n := re.FindString(name.Domain)
			if n == "" {
				continue
			}

			c.Bus().Publish(core.NewNameTopic, &core.Request{
				Name:   cleanName(n),
				Domain: domain,
				Tag:    c.SourceType,
				Source: c.String(),
			})
		}
	}
}

func (c *CertDB) getAuthURL() string {
	return "https://account.spyse.com/login"
}

func (c *CertDB) getAuthBody() string {
	return fmt.Sprintf("Login[email]=%s&Login[password]=%s", c.API.Username, c.API.Password)
}

func (c *CertDB) getURL(domain string) string {
	u, _ := url.Parse("https://certdb.com/show-more/")

	u.RawQuery = url.Values{
		"from_url": {fmt.Sprintf("https://certdb.com/search?q=%s", domain)},
		"page":     {"1"},
	}.Encode()
	return u.String()
}

func (c *CertDB) authenticate() {
	u := c.getAuthURL()
	body := strings.NewReader(c.getAuthBody())
	headers := map[string]string{
		"Content-Type": "application/x-www-form-urlencoded",
	}
	_, err := utils.RequestWebPage(u, body, headers, "", "")
	if err != nil {
		c.Config().Log.Printf("%s: Could not authenticate", c.String())
		return
	}
	utils.CopyCookies("http://account.spyse.com", "http://certdb.com")
}
