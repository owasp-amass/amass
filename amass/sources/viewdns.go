// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
)

// ViewDNS is the Service that handles access to the ViewDNS data source.
type ViewDNS struct {
	core.BaseService

	SourceType string
	RateLimit  time.Duration
}

// NewViewDNS returns he object initialized, but not yet started.
func NewViewDNS(config *core.Config, bus *core.EventBus) *ViewDNS {
	v := &ViewDNS{
		SourceType: core.SCRAPE,
		RateLimit:  10 * time.Second,
	}

	v.BaseService = *core.NewBaseService(v, "ViewDNS", config, bus)
	return v
}

// OnStart implements the Service interface
func (v *ViewDNS) OnStart() error {
	v.BaseService.OnStart()

	v.Bus().Subscribe(core.WhoisRequestTopic, v.SendWhoisRequest)
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
		v.Config().Log.Printf("%s: %s: %v", v.String(), u, err)
		return
	}

	// Look for IP addresses in the web page returned
	re := regexp.MustCompile(utils.IPv4RE)
	for _, sd := range re.FindAllString(page, -1) {
		addr := utils.NewUniqueElements(unique, sd)

		if len(addr) > 0 {
			v.Bus().Publish(core.NewAddrTopic, &core.AddrRequest{
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
		v.Config().Log.Printf("%s: %s: %v", v.String(), u, err)
		return
	}
	// Pull the table we need from the page content
	table := getViewDNSTable(page)
	if table == "" {
		v.Config().Log.Printf("%s: %s: Failed to discover the table of results", v.String(), u)
		return
	}
	// Get the list of domain names discovered through the reverse DNS service
	re := regexp.MustCompile("<tr><td>([a-zA-Z0-9]{1}[a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1}[.]{1}[a-zA-Z0-9-]+)</td><td>")
	subs := re.FindAllStringSubmatch(table, -1)

	var matches []string
	for _, match := range subs {
		sub := match[1]
		if sub != "" {
			matches = utils.UniqueAppend(matches, strings.TrimSpace(sub))
		}
	}

	if len(matches) > 0 {
		v.Bus().Publish(core.NewWhoisTopic, &core.WhoisRequest{
			Domain:     domain,
			NewDomains: matches,
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
