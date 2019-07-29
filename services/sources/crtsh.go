// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq" // Need the postgres driver
)

// Crtsh is the Service that handles access to the Crtsh data source.
type Crtsh struct {
	services.BaseService

	SourceType     string
	db             *sqlx.DB
	haveConnection bool
}

// NewCrtsh returns he object initialized, but not yet started.
func NewCrtsh(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Crtsh {
	c := &Crtsh{
		SourceType:     requests.CERT,
		haveConnection: true,
	}

	c.BaseService = *services.NewBaseService(c, "Crtsh", cfg, bus, pool)
	return c
}

// OnStart implements the Service interface
func (c *Crtsh) OnStart() error {
	c.BaseService.OnStart()

	var err error
	c.db, err = sqlx.Connect("postgres", "host=crt.sh user=guest dbname=certwatch sslmode=disable")
	if err != nil {
		c.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to connect to the database server: %v", c.String(), err),
		)
		c.haveConnection = false
	}

	go c.processRequests()
	return nil
}

func (c *Crtsh) processRequests() {
	for {
		select {
		case <-c.Quit():
			return
		case req := <-c.DNSRequestChan():
			if c.Config().IsDomainInScope(req.Domain) {
				c.executeQuery(req.Domain)
			}
		case <-c.AddrRequestChan():
		case <-c.ASNRequestChan():
		case <-c.WhoisRequestChan():
		}
	}
}

func (c *Crtsh) executeQuery(domain string) {
	// Fall back to scraping the web page if the database connection failed
	if !c.haveConnection {
		c.scrape(domain)
		return
	}

	var results []struct {
		Domain string `db:"domain"`
	}

	pattern := "%." + domain
	err := c.db.Select(&results,
		`SELECT DISTINCT ci.NAME_VALUE as domain
		FROM certificate_identity ci
		WHERE reverse(lower(ci.NAME_VALUE)) LIKE reverse(lower($1))
		ORDER BY ci.NAME_VALUE`, pattern)
	if err != nil {
		c.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: Query pattern %s: %v", c.String(), pattern, err))
		return
	}

	c.SetActive()
	// Extract the subdomain names from the results
	var names []string
	for _, result := range results {
		names = utils.UniqueAppend(names, strings.ToLower(utils.RemoveAsteriskLabel(result.Domain)))
	}

	for _, name := range names {
		c.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    c.SourceType,
			Source: c.String(),
		})
	}
}

func (c *Crtsh) scrape(domain string) {
	url := c.getURL(domain)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		c.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", c.String(), url, err))
		return
	}

	c.SetActive()
	// Extract the subdomain names from the results
	var results []struct {
		Name string `json:"name_value"`
	}
	if err := json.Unmarshal([]byte(page), &results); err != nil {
		return
	}
	for _, line := range results {
		c.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   line.Name,
			Domain: domain,
			Tag:    c.SourceType,
			Source: c.String(),
		})
	}
}

func (c *Crtsh) getURL(domain string) string {
	return "https://crt.sh/?q=%25." + domain + "&output=json"
}
