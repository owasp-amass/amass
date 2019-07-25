// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// ViewDNS is the Service that handles access to the ViewDNS data source.
type ViewDNS struct {
	services.BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewViewDNS returns he object initialized, but not yet started.
func NewViewDNS(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *ViewDNS {
	v := &ViewDNS{
		SourceType: requests.SCRAPE,
		RateLimit:  10 * time.Second,
	}

	v.BaseService = *services.NewBaseService(v, "ViewDNS", cfg, bus, pool)
	return v
}

// OnStart implements the Service interface
func (v *ViewDNS) OnStart() error {
	v.BaseService.OnStart()

	v.Bus().Subscribe(requests.WhoisRequestTopic, v.SendWhoisRequest)
	go v.processRequests()
	return nil
}

func (v *ViewDNS) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)

	for {
		select {
		case <-v.Quit():
			return
		case dns := <-v.DNSRequestChan():
			if v.Config().IsDomainInScope(dns.Domain) {
				if time.Now().Sub(last) < v.RateLimit {
					time.Sleep(v.RateLimit)
				}
				last = time.Now()
				v.executeDNSQuery(dns.Domain)
				last = time.Now()
			}
		case whois := <-v.WhoisRequestChan():
			if v.Config().IsDomainInScope(whois.Domain) {
				if time.Now().Sub(last) < v.RateLimit {
					time.Sleep(v.RateLimit)
				}
				last = time.Now()
				v.executeWhoisQuery(whois.Domain)
				last = time.Now()
			}
		case <-v.AddrRequestChan():
		case <-v.ASNRequestChan():
		}
	}
}

func (v *ViewDNS) executeDNSQuery(domain string) {
	var unique []string

	u := "http://viewdns.info/iphistory/?domain=" + domain
	// The ViewDNS IP History lookup sometimes reveals interesting results
	page, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		v.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", v.String(), u, err))
		return
	}

	// Look for IP addresses in the web page returned
	re := regexp.MustCompile(utils.IPv4RE)
	for _, sd := range re.FindAllString(page, -1) {
		addr := utils.NewUniqueElements(unique, sd)

		if len(addr) > 0 {
			v.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
				Address: addr[0],
				Domain:  domain,
				Tag:     v.SourceType,
				Source:  v.String(),
			})
		}
	}
}

func (v *ViewDNS) executeWhoisQuery(domain string) {
	u := v.getURL(domain)
	page, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		v.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", v.String(), u, err))
		return
	}
	// Pull the table we need from the page content
	table := getViewDNSTable(page)
	if table == "" {
		v.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: %s: Failed to discover the table of results", v.String(), u),
		)
		return
	}
	// Get the list of domain names discovered through the reverse DNS service
	re := regexp.MustCompile("<tr><td>([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1}[.]{1}[a-zA-Z0-9-]+)</td><td>")
	subs := re.FindAllStringSubmatch(table, -1)

	matches := utils.NewSet()
	for _, match := range subs {
		sub := match[1]
		if sub != "" {
			matches.Insert(strings.TrimSpace(sub))
		}
	}

	if matches.Len() > 0 {
		v.Bus().Publish(requests.NewWhoisTopic, &requests.WhoisRequest{
			Domain:     domain,
			NewDomains: matches.ToSlice(),
			Tag:        v.SourceType,
			Source:     v.String(),
		})
	}
}

func (v *ViewDNS) getURL(domain string) string {
	format := "http://viewdns.info/reversewhois/?q=%s"

	return fmt.Sprintf(format, domain)
}

func getViewDNSTable(page string) string {
	var begin, end int

	s := page
	for i := 0; i < 4; i++ {
		b := strings.Index(s, "<table")
		if b == -1 {
			return ""
		}
		begin += b + 6

		if e := strings.Index(s[b:], "</table>"); e != -1 {
			end = begin + e
		} else {
			return ""
		}
		s = page[end+8:]
	}
	i := strings.Index(page[begin:end], "<table")
	i = strings.Index(page[begin+i+6:end], "<table")
	return page[begin+i : end]
}
