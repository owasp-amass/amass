// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// GoogleCT is the Service that handles access to the GoogleCT data source.
type GoogleCT struct {
	BaseService

	SourceType string
	baseURL    string
	tokenRE    *regexp.Regexp
}

// NewGoogleCT returns he object initialized, but not yet started.
func NewGoogleCT(sys System) *GoogleCT {
	g := &GoogleCT{
		SourceType: requests.CERT,
		baseURL:    "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch",
	}

	g.tokenRE = regexp.MustCompile(`\[(null|"[a-zA-Z0-9]+"),"([a-zA-Z0-9]+)",null,([0-9]+),([0-9]+)\]`)
	if g.tokenRE == nil {
		return nil
	}

	g.BaseService = *NewBaseService(g, "GoogleCT", sys)
	return g
}

// Type implements the Service interface.
func (g *GoogleCT) Type() string {
	return g.SourceType
}

// OnStart implements the Service interface.
func (g *GoogleCT) OnStart() error {
	g.BaseService.OnStart()

	g.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (g *GoogleCT) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", g.String(), req.Domain))

	var token string
	for {
		bus.Publish(requests.SetActiveTopic, g.String())

		u := g.getDNSURL(req.Domain, token)
		headers := map[string]string{
			"Connection": "close",
			"Referer":    "https://transparencyreport.google.com/https/certificates",
		}
		page, err := http.RequestWebPage(u, nil, headers, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", g.String(), u, err))
			break
		}

		for _, name := range re.FindAllString(page, -1) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: req.Domain,
				Tag:    g.SourceType,
				Source: g.String(),
			})
		}

		token = ""
		if match := g.tokenRE.FindStringSubmatch(page); len(match) == 5 && match[3] != match[4] {
			token = match[2]
		}
		if token == "" {
			break
		}

		g.CheckRateLimit()
	}
}

func (g *GoogleCT) getDNSURL(domain, token string) string {
	var dir string

	if token != "" {
		dir = "/page"
	}
	u, _ := url.Parse(g.baseURL + dir)

	values := url.Values{
		"domain":             {domain},
		"include_expired":    {"true"},
		"include_subdomains": {"true"},
	}

	if token != "" {
		values.Add("p", token)
	}

	u.RawQuery = values.Encode()
	return u.String()
}
