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

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// AlienVault is the Service that handles access to the AlienVault data source.
type AlienVault struct {
	core.BaseService

	API        *core.APIKey
	SourceType string
	RateLimit  time.Duration

	haveAPIKey bool
}

// NewAlienVault returns he object initialized, but not yet started.
func NewAlienVault(config *core.Config, bus *core.EventBus) *AlienVault {
	a := &AlienVault{
		SourceType: core.API,
		RateLimit:  100 * time.Millisecond,
		haveAPIKey: true,
	}

	a.BaseService = *core.NewBaseService(a, "AlienVault", config, bus)
	return a
}

// OnStart implements the Service interface
func (a *AlienVault) OnStart() error {
	a.BaseService.OnStart()

	a.API = a.Config().GetAPIKey(a.String())
	if a.API == nil || a.API.Key == "" {
		a.haveAPIKey = false
		a.Config().Log.Printf("%s: API key data was not provided", a.String())
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
			if a.haveAPIKey && a.Config().IsDomainInScope(req.Domain) {
				if time.Now().Sub(last) < a.RateLimit {
					time.Sleep(a.RateLimit)
				}
				last = time.Now()
				a.executeQuery(req.Domain)
				last = time.Now()
			}
		case <-a.AddrRequestChan():
		case <-a.ASNRequestChan():
		case <-a.WhoisRequestChan():
		}
	}
}

func (a *AlienVault) executeQuery(domain string) {
	re := a.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	a.SetActive()
	u := a.getURL(domain) + "passive_dns"
	headers := map[string]string{"Content-Type": "application/json", "X-OTX-API-KEY": a.API.Key}
	page, err := utils.RequestWebPage(u, nil, headers, "", "")
	if err != nil {
		a.Config().Log.Printf("%s: %s: %v", a.String(), u, err)
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
		return
	}

	var names []string
	var ips []string
	if len(m.Subdomains) != 0 {
		for _, sub := range m.Subdomains {
			n := strings.ToLower(sub.Hostname)

			if re.MatchString(n) {
				names = append(names, n)
				ips = append(ips, sub.IP)
			}
		}
	}

	time.Sleep(a.RateLimit)
	u = a.getURL(domain) + "url_list"
	page, err = utils.RequestWebPage(u, nil, headers, "", "")
	if err != nil {
		a.Config().Log.Printf("%s: %s: %v", a.String(), u, err)
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
		return
	}

	if len(urls.URLs) != 0 {
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
	// If there are additional pages of URLs, obtain that info as well
	if urls.HasNext {
		pages := int(math.Ceil(float64(urls.FullSize) / float64(urls.Limit)))
		for cur := urls.PageNum + 1; cur <= pages; cur++ {
			time.Sleep(a.RateLimit)
			pageURL := u + "?page=" + strconv.Itoa(cur)
			page, err = utils.RequestWebPage(pageURL, nil, headers, "", "")
			if err != nil {
				a.Config().Log.Printf("%s: %s: %v", a.String(), pageURL, err)
				break
			}

			if err := json.Unmarshal([]byte(page), &urls); err != nil {
				break
			}

			if len(urls.URLs) != 0 {
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
	}

	for _, name := range names {
		a.Bus().Publish(core.NewNameTopic, &core.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    a.SourceType,
			Source: a.String(),
		})
	}

	for _, ip := range ips {
		a.Bus().Publish(core.NewAddrTopic, &core.AddrRequest{
			Address: ip,
			Tag:     a.SourceType,
			Source:  a.String(),
		})
	}
}

func (a *AlienVault) getURL(domain string) string {
	format := "https://otx.alienvault.com/api/v1/indicators/domain/%s/"

	return fmt.Sprintf(format, domain)
}
