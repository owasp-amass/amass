// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// CIRCL is the Service that handles access to the CIRCL data source.
type CIRCL struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewCIRCL returns he object initialized, but not yet started.
func NewCIRCL(sys System) *CIRCL {
	c := &CIRCL{SourceType: requests.API}

	c.BaseService = *NewBaseService(c, "CIRCL", sys)
	return c
}

// Type implements the Service interface.
func (c *CIRCL) Type() string {
	return c.SourceType
}

// OnStart implements the Service interface.
func (c *CIRCL) OnStart() error {
	c.BaseService.OnStart()

	c.API = c.System().Config().GetAPIKey(c.String())
	if c.API == nil || c.API.Username == "" || c.API.Password == "" {
		c.System().Config().Log.Printf("%s: API key data was not provided", c.String())
	}

	c.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (c *CIRCL) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	if c.API == nil || c.API.Username == "" || c.API.Password == "" {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	unique := stringset.New()
	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	c.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, c.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", c.String(), req.Domain))

	url := c.restURL(req.Domain)
	headers := map[string]string{"Content-Type": "application/json"}
	page, err := http.RequestWebPage(url, nil, headers, c.API.Username, c.API.Password)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", c.String(), url, err))
		return
	}

	bus.Publish(requests.SetActiveTopic, c.String())
	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j struct {
			Name string `json:"rrname"`
		}
		err := json.Unmarshal([]byte(line), &j)
		if err != nil {
			continue
		}
		if re.MatchString(j.Name) {
			unique.Insert(j.Name)
		}
	}

	for name := range unique {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    c.SourceType,
			Source: c.String(),
		})
	}
}

func (c *CIRCL) restURL(domain string) string {
	return "https://www.circl.lu/pdns/query/" + domain
}
