// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/caffix/stringset"
)

// AlienVault is the Service that handles access to the AlienVault data source.
type AlienVault struct {
	service.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

// NewAlienVault returns he object initialized, but not yet started.
func NewAlienVault(sys systems.System) *AlienVault {
	a := &AlienVault{
		SourceType: requests.API,
		sys:        sys,
	}

	a.BaseService = *service.NewBaseService(a, "AlienVault")
	return a
}

// Description implements the Service interface.
func (a *AlienVault) Description() string {
	return a.SourceType
}

// OnStart implements the Service interface.
func (a *AlienVault) OnStart() error {
	a.creds = a.sys.Config().GetDataSourceConfig(a.String()).GetCredentials()

	if a.creds == nil {
		a.sys.Config().Log.Printf("%s: API key data was not provided", a.String())
	}

	a.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (a *AlienVault) OnRequest(ctx context.Context, args service.Args) {
	switch req := args.(type) {
	case *requests.DNSRequest:
		a.dnsRequest(ctx, req)
	case *requests.WhoisRequest:
		a.whoisRequest(ctx, req)
	}
}

func (a *AlienVault) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	if !a.sys.Config().IsDomainInScope(req.Domain) {
		return
	}

	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", a.String(), req.Domain))
	a.executeDNSQuery(ctx, req)

	a.CheckRateLimit()
	a.executeURLQuery(ctx, req)
}

func (a *AlienVault) whoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	if !a.sys.Config().IsDomainInScope(req.Domain) {
		return
	}

	a.executeWhoisQuery(ctx, req)
}

func (a *AlienVault) executeDNSQuery(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	u := a.getURL(req.Domain) + "passive_dns"
	page, err := http.RequestWebPage(u, nil, a.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	}
	// Extract the subdomain names and IP addresses from the passive DNS information
	var m struct {
		Subdomains []struct {
			Hostname string `json:"hostname"`
			IP       string `json:"address"`
		} `json:"passive_dns"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	} else if len(m.Subdomains) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
		return
	}

	ips := stringset.New()
	names := stringset.New()
	for _, sub := range m.Subdomains {
		n := strings.ToLower(sub.Hostname)

		if re.MatchString(n) {
			names.Insert(n)
			if ip := net.ParseIP(sub.IP); ip != nil {
				ips.Insert(ip.String())
			}
		}
	}

	for name := range names {
		genNewNameEvent(ctx, a.sys, a, name)
	}

	for ip := range ips {
		bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
			Address: ip,
			Domain:  req.Domain,
			Tag:     a.SourceType,
			Source:  a.String(),
		})
	}
}

type avURL struct {
	Domain   string `json:"domain"`
	Hostname string `json:"hostname"`
	Result   struct {
		Worker struct {
			IP string `json:"ip"`
		} `json:"urlworker"`
	} `json:"result"`
}

func (a *AlienVault) executeURLQuery(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	headers := a.getHeaders()
	u := a.getURL(req.Domain) + "url_list"
	page, err := http.RequestWebPage(u, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	}
	// Extract the subdomain names and IP addresses from the URL information
	var m struct {
		PageNum  int     `json:"page_num"`
		HasNext  bool    `json:"has_next"`
		Limit    int     `json:"limit"`
		FullSize int     `json:"full_size"`
		URLs     []avURL `json:"url_list"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	} else if len(m.URLs) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
		return
	}

	ips := stringset.New()
	names := stringset.New()
	extractNamesIPs(m.URLs, names, ips, re)
	// If there are additional pages of URLs, obtain that info as well
	if m.HasNext {
		pages := int(math.Ceil(float64(m.FullSize) / float64(m.Limit)))
		for cur := m.PageNum + 1; cur <= pages; cur++ {
			a.CheckRateLimit()
			pageURL := u + "?page=" + strconv.Itoa(cur)
			page, err = http.RequestWebPage(pageURL, nil, headers, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
					fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
				break
			}

			if err := json.Unmarshal([]byte(page), &m); err != nil {
				bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
					fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
				break
			} else if len(m.URLs) == 0 {
				bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
					fmt.Sprintf("%s: %s: The query returned zero results", a.String(), pageURL),
				)
				break
			}

			extractNamesIPs(m.URLs, names, ips, re)
		}
	}

	for name := range names {
		genNewNameEvent(ctx, a.sys, a, name)
	}

	for ip := range ips {
		bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
			Address: ip,
			Domain:  req.Domain,
			Tag:     a.SourceType,
			Source:  a.String(),
		})
	}
}

func extractNamesIPs(urls []avURL, names stringset.Set, ips stringset.Set, re *regexp.Regexp) {
	for _, u := range urls {
		n := strings.ToLower(u.Hostname)

		if re.MatchString(n) {
			names.Insert(n)
			if ip := net.ParseIP(u.Result.Worker.IP); ip != nil {
				ips.Insert(ip.String())
			}
		}
	}
}

func (a *AlienVault) executeWhoisQuery(ctx context.Context, req *requests.WhoisRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	emails := a.queryWhoisForEmails(ctx, req)
	a.CheckRateLimit()

	newDomains := stringset.New()
	headers := a.getHeaders()
	for _, email := range emails {
		pageURL := a.getReverseWhoisURL(email)
		page, err := http.RequestWebPage(pageURL, nil, headers, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
				fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
			continue
		}

		type record struct {
			Domain string `json:"domain"`
		}
		var domains []record
		if err := json.Unmarshal([]byte(page), &domains); err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
				fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
			continue
		}
		for _, d := range domains {
			if !cfg.IsDomainInScope(d.Domain) {
				newDomains.Insert(d.Domain)
			}
		}
		a.CheckRateLimit()
	}

	if len(newDomains) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: Reverse whois failed to discover new domain names for %s", a.String(), req.Domain),
		)
		return
	}

	bus.Publish(requests.NewWhoisTopic, eventbus.PriorityHigh, &requests.WhoisRequest{
		Domain:     req.Domain,
		NewDomains: newDomains.Slice(),
		Tag:        a.SourceType,
		Source:     a.String(),
	})
}

func (a *AlienVault) queryWhoisForEmails(ctx context.Context, req *requests.WhoisRequest) []string {
	emails := stringset.New()
	u := a.getWhoisURL(req.Domain)

	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return emails.Slice()
	}

	page, err := http.RequestWebPage(u, nil, a.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return emails.Slice()
	}

	var m struct {
		Count int `json:"count"`
		Data  []struct {
			Value string `json:"value"`
			Name  string `json:"name"`
			Key   string `json:"key"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(page), &m); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return emails.Slice()
	} else if m.Count == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
		return emails.Slice()
	}

	for _, row := range m.Data {
		if strings.TrimSpace(row.Key) == "emails" {
			email := strings.TrimSpace(row.Value)
			emailParts := strings.Split(email, "@")
			if len(emailParts) != 2 {
				continue
			}
			d := emailParts[1]

			// Unfortunately AlienVault doesn't categorize the email addresses so we
			// have to filter by something we know to avoid adding registrar emails
			if cfg.IsDomainInScope(d) {
				emails.Insert(email)
			}
		}
	}
	return emails.Slice()
}

func (a *AlienVault) getHeaders() map[string]string {
	headers := map[string]string{"Content-Type": "application/json"}

	if a.creds != nil && a.creds.Key != "" {
		headers["X-OTX-API-KEY"] = a.creds.Key
	}
	return headers
}

func (a *AlienVault) getWhoisURL(domain string) string {
	// https://otx.alienvault.com/otxapi/indicator/domain/whois/google.com
	return "https://otx.alienvault.com/otxapi/indicator/domain/whois/" + domain
}

func (a *AlienVault) getReverseWhoisURL(email string) string {
	return "https://otx.alienvault.com/otxapi/indicator/email/whois/" + email
}

func (a *AlienVault) getURL(domain string) string {
	format := "https://otx.alienvault.com/api/v1/indicators/domain/%s/"

	return fmt.Sprintf(format, domain)
}
