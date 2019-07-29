// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// AlienVault is the Service that handles access to the AlienVault data source.
type AlienVault struct {
	services.BaseService

	API        *config.APIKey
	SourceType string
	RateLimit  time.Duration
}

// NewAlienVault returns he object initialized, but not yet started.
func NewAlienVault(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *AlienVault {
	a := &AlienVault{
		SourceType: requests.API,
		RateLimit:  100 * time.Millisecond,
	}

	a.BaseService = *services.NewBaseService(a, "AlienVault", cfg, bus, pool)
	return a
}

// OnStart implements the Service interface
func (a *AlienVault) OnStart() error {
	a.BaseService.OnStart()

	a.API = a.Config().GetAPIKey(a.String())
	if a.API == nil || a.API.Key == "" {
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: API key data was not provided", a.String()))
	}

	go a.processRequests()
	return nil
}

func (a *AlienVault) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)

	for {
		select {
		case <-a.Quit():
			return
		case req := <-a.DNSRequestChan():
			if a.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < a.RateLimit {
					time.Sleep(a.RateLimit)
				}
				last = time.Now()
				a.executeDNSQuery(req.Domain)
				time.Sleep(a.RateLimit)
				a.executeURLQuery(req.Domain)
				last = time.Now()
			}
		case <-a.AddrRequestChan():
		case <-a.ASNRequestChan():
		case req := <-a.WhoisRequestChan():
			if a.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < a.RateLimit {
					time.Sleep(a.RateLimit)
				}
				last = time.Now()
				a.executeWhoisQuery(req.Domain)
				last = time.Now()
			}
		}
	}
}

func (a *AlienVault) executeDNSQuery(domain string) {
	re := a.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	a.SetActive()
	u := a.getURL(domain) + "passive_dns"
	page, err := utils.RequestWebPage(u, nil, a.getHeaders(), "", "")
	if err != nil {
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
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
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	} else if len(m.Subdomains) == 0 {
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
		return
	}

	var ips []string
	var names []string
	for _, sub := range m.Subdomains {
		n := strings.ToLower(sub.Hostname)

		if re.MatchString(n) {
			names = append(names, n)
			ips = append(ips, sub.IP)
		}
	}

	for _, name := range names {
		a.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}

	for _, ip := range ips {
		a.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Tag:     a.SourceType,
			Source:  a.String(),
		})
	}
}

func (a *AlienVault) executeURLQuery(domain string) {
	re := a.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	a.SetActive()
	headers := a.getHeaders()
	u := a.getURL(domain) + "url_list"
	page, err := utils.RequestWebPage(u, nil, headers, "", "")
	if err != nil {
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
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
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return
	} else if len(urls.URLs) == 0 {
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u))
		return
	}

	var ips []string
	var names []string
	for _, u := range urls.URLs {
		n := strings.ToLower(u.Hostname)

		if re.MatchString(n) {
			names = utils.UniqueAppend(names, n)
			if u.Result.Worker.IP != "" {
				ips = utils.UniqueAppend(ips, u.Result.Worker.IP)
			}
		}
	}
	// If there are additional pages of URLs, obtain that info as well
	if urls.HasNext {
		pages := int(math.Ceil(float64(urls.FullSize) / float64(urls.Limit)))
		for cur := urls.PageNum + 1; cur <= pages; cur++ {
			time.Sleep(a.RateLimit)
			pageURL := u + "?page=" + strconv.Itoa(cur)
			page, err = utils.RequestWebPage(pageURL, nil, headers, "", "")
			if err != nil {
				a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
				break
			}

			if err := json.Unmarshal([]byte(page), &urls); err != nil {
				a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
				break
			} else if len(urls.URLs) == 0 {
				a.Bus().Publish(requests.LogTopic,
					fmt.Sprintf("%s: %s: The query returned zero results", a.String(), pageURL),
				)
				break
			}

			for _, u := range urls.URLs {
				n := strings.ToLower(u.Hostname)

				if re.MatchString(n) {
					names = utils.UniqueAppend(names, n)
					if u.Result.Worker.IP != "" {
						ips = utils.UniqueAppend(ips, u.Result.Worker.IP)
					}
				}
			}
		}
	}

	for _, name := range names {
		a.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}

	for _, ip := range ips {
		a.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Tag:     a.SourceType,
			Source:  a.String(),
		})
	}
}

func (a *AlienVault) queryWhoisForEmails(domain string) []string {
	var emails []string
	u := a.getWhoisURL(domain)

	a.SetActive()
	page, err := utils.RequestWebPage(u, nil, a.getHeaders(), "", "")
	if err != nil {
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return emails
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
		a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), u, err))
		return emails
	} else if m.Count == 0 {
		a.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: The query returned zero results", a.String(), u),
		)
		return emails
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
			if a.Config().IsDomainInScope(d) {
				emails = utils.UniqueAppend(emails, email)
			}
		}
	}
	return emails
}

func (a *AlienVault) executeWhoisQuery(domain string) {
	emails := a.queryWhoisForEmails(domain)
	time.Sleep(a.RateLimit)

	var newDomains []string
	headers := a.getHeaders()
	for _, email := range emails {
		a.SetActive()
		pageURL := a.getReverseWhoisURL(email)
		page, err := utils.RequestWebPage(pageURL, nil, headers, "", "")
		if err != nil {
			a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
			continue
		}

		type record struct {
			Domain string `json:"domain"`
		}
		var domains []record
		if err := json.Unmarshal([]byte(page), &domains); err != nil {
			a.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", a.String(), pageURL, err))
			continue
		}
		for _, d := range domains {
			if !a.Config().IsDomainInScope(d.Domain) {
				newDomains = utils.UniqueAppend(newDomains, d.Domain)
			}
		}
		time.Sleep(a.RateLimit)
	}

	if len(newDomains) == 0 {
		a.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: Reverse whois failed to discover new domain names for %s", a.String(), domain),
		)
		return
	}

	a.Bus().Publish(requests.NewWhoisTopic, &requests.WhoisRequest{
		Domain:     domain,
		NewDomains: newDomains,
		Tag:        a.SourceType,
		Source:     a.String(),
	})
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
