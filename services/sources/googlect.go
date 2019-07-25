// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"net/url"
	"regexp"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// GoogleCT is the Service that handles access to the GoogleCT data source.
type GoogleCT struct {
	services.BaseService

	SourceType string
	baseURL    string
	tokenRE    *regexp.Regexp
}

// NewGoogleCT returns he object initialized, but not yet started.
func NewGoogleCT(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *GoogleCT {
	g := &GoogleCT{
		SourceType: requests.CERT,
		baseURL:    "https://www.google.com/transparencyreport/api/v3/httpsreport/ct/certsearch",
	}

	g.tokenRE = regexp.MustCompile(`\[(null|"[a-zA-Z0-9]+"),"([a-zA-Z0-9]+)",null,([0-9]+),([0-9]+)\]`)
	if g.tokenRE == nil {
		return nil
	}

	g.BaseService = *services.NewBaseService(g, "GoogleCT", cfg, bus, pool)
	return g
}

// OnStart implements the Service interface
func (g *GoogleCT) OnStart() error {
	g.BaseService.OnStart()

	go g.processRequests()
	return nil
}

func (g *GoogleCT) processRequests() {
	for {
		select {
		case <-g.Quit():
			return
		case dns := <-g.DNSRequestChan():
			if g.Config().IsDomainInScope(dns.Domain) {
				g.executeDNSQuery(dns.Domain)
			}
		case <-g.ASNRequestChan():
		case <-g.AddrRequestChan():
		case <-g.WhoisRequestChan():
		}
	}
}

func (g *GoogleCT) executeDNSQuery(domain string) {
	re := g.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	var token string
	for {
		g.SetActive()
		u := g.getDNSURL(domain, token)
		headers := map[string]string{
			"Connection": "close",
			"Referer":    "https://transparencyreport.google.com/https/certificates",
		}
		page, err := utils.RequestWebPage(u, nil, headers, "", "")
		if err != nil {
			g.Config().Log.Printf("%s: %s: %v", g.String(), u, err)
			break
		}

		for _, name := range re.FindAllString(page, -1) {
			g.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
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
		time.Sleep(time.Second)
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
