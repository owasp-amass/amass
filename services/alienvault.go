// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// AlienVault is the Service that handles access to the AlienVault data source.
type AlienVault struct {
	BaseService

	API        *config.APIKey
	SourceType string
}

// NewAlienVault returns he object initialized, but not yet started.
func NewAlienVault(sys System) *AlienVault {
	a := &AlienVault{SourceType: requests.API}

	a.BaseService = *NewBaseService(a, "AlienVault", sys)
	return a
}

// Type implements the Service interface.
func (a *AlienVault) Type() string {
	return a.SourceType
}

// OnStart implements the Service interface.
func (a *AlienVault) OnStart() error {
	a.BaseService.OnStart()

	a.API = a.System().Config().GetAPIKey(a.String())

	if a.API == nil || a.API.Key == "" {
		a.System().Config().Log.Printf("%s: API key data was not provided", a.String())
	}

	a.SetRateLimit(100 * time.Millisecond)
	return nil
}

// OnDNSRequest implements the Service interface.
func (a *AlienVault) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	if !a.System().Config().IsDomainInScope(req.Domain) {
		return
	}

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	a.CheckRateLimit()
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", a.String(), req.Domain))
	a.executeDNSQuery(ctx, req)

	a.CheckRateLimit()
	a.executeURLQuery(ctx, req)
}

// OnWhoisRequest implements the Service interface.
func (a *AlienVault) OnWhoisRequest(ctx context.Context, req *requests.WhoisRequest) {
	if !a.System().Config().IsDomainInScope(req.Domain) {
		return
	}

	a.CheckRateLimit()
	a.executeWhoisQuery(ctx, req)
}

func (a *AlienVault) executeDNSQuery(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, a.String())

	u := a.getURL(req.Domain) + "passive_dns"
	page, err := http.RequestWebPage(u, nil, a.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
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
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	} else if len(m.Subdomains) == 0 {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
		return
	}

	ips := stringset.New()
	names := stringset.New()
	for _, sub := range m.Subdomains {
		n := strings.ToLower(sub.Hostname)

		if re.MatchString(n) {
			names.Insert(n)
			ips.Insert(sub.IP)
		}
	}

	for name := range names {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}

	for ip := range ips {
		bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Domain:  req.Domain,
			Tag:     a.SourceType,
			Source:  a.String(),
		})
	}
}

func (a *AlienVault) executeURLQuery(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, a.String())

	headers := a.getHeaders()
	u := a.getURL(req.Domain) + "url_list"
	page, err := http.RequestWebPage(u, nil, headers, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	}
	// Extract the subdomain names and IP addresses from the URL information
	var urls struct {
		PageNum  int  `json:"page_num"`
		HasNext  bool `json:"has_next"`
		Limit    int  `json:"limit"`
		FullSize int  `json:"full_size"`
		URLs     []struct {
			Domain   string `json:"domain"`
			Hostname string `json:"hostname"`
			Result   struct {
				Worker struct {
					IP string `json:"ip"`
				} `json:"urlworker"`
			} `json:"result"`
		} `json:"url_list"`
	}
	if err := json.Unmarshal([]byte(page), &urls); err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	} else if len(urls.URLs) == 0 {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
		return
	}

	ips := stringset.New()
	names := stringset.New()
	for _, u := range urls.URLs {
		n := strings.ToLower(u.Hostname)

		if re.MatchString(n) {
			names.Insert(n)
			if u.Result.Worker.IP != "" {
				ips.Insert(u.Result.Worker.IP)
			}
		}
	}
	// If there are additional pages of URLs, obtain that info as well
	if urls.HasNext {
		pages := int(math.Ceil(float64(urls.FullSize) / float64(urls.Limit)))
		for cur := urls.PageNum + 1; cur <= pages; cur++ {
			a.CheckRateLimit()
			pageURL := u + "?page=" + strconv.Itoa(cur)
			page, err = http.RequestWebPage(pageURL, nil, headers, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
				break
			}

			if err := json.Unmarshal([]byte(page), &urls); err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
				break
			} else if len(urls.URLs) == 0 {
				bus.Publish(requests.LogTopic,
					fmt.Sprintf("%s: %s: The query returned zero results", a.String(), pageURL),
				)
				break
			}

			for _, u := range urls.URLs {
				n := strings.ToLower(u.Hostname)

				if re.MatchString(n) {
					names.Insert(n)
					if u.Result.Worker.IP != "" {
						ips.Insert(u.Result.Worker.IP)
					}
				}
			}
		}
	}

	for name := range names {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}

	for ip := range ips {
		bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Domain:  req.Domain,
			Tag:     a.SourceType,
			Source:  a.String(),
		})
	}
}

func (a *AlienVault) executeWhoisQuery(ctx context.Context, req *requests.WhoisRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	emails := a.queryWhoisForEmails(ctx, req)
	a.CheckRateLimit()

	newDomains := stringset.New()
	headers := a.getHeaders()
	for _, email := range emails {
		bus.Publish(requests.SetActiveTopic, a.String())

		pageURL := a.getReverseWhoisURL(email)
		page, err := http.RequestWebPage(pageURL, nil, headers, "", "")
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
			continue
		}

		type record struct {
			Domain string `json:"domain"`
		}
		var domains []record
		if err := json.Unmarshal([]byte(page), &domains); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
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
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: Reverse whois failed to discover new domain names for %s", a.String(), req.Domain),
		)
		return
	}

	bus.Publish(requests.NewWhoisTopic, &requests.WhoisRequest{
		Domain:     req.Domain,
		NewDomains: newDomains.Slice(),
		Tag:        a.SourceType,
		Source:     a.String(),
	})
}

func (a *AlienVault) queryWhoisForEmails(ctx context.Context, req *requests.WhoisRequest) []string {
	emails := stringset.New()
	u := a.getWhoisURL(req.Domain)

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return emails.Slice()
	}

	bus.Publish(requests.SetActiveTopic, a.String())

	page, err := http.RequestWebPage(u, nil, a.getHeaders(), "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
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
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return emails.Slice()
	} else if m.Count == 0 {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
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

	if a.API != nil && a.API.Key != "" {
		headers["X-OTX-API-KEY"] = a.API.Key
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
