// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"time"
)

type IPHistoryService struct {
	BaseAmassService

	// Do not lookup the same domain name multiple times
	filter map[string]struct{}
}

func NewIPHistoryService(in, out chan *AmassRequest, config *AmassConfig) *IPHistoryService {
	ihs := &IPHistoryService{filter: make(map[string]struct{})}

	ihs.BaseAmassService = *NewBaseAmassService("IP History Service", config, ihs)

	ihs.input = in
	ihs.output = out
	return ihs
}

func (ihs *IPHistoryService) OnStart() error {
	ihs.BaseAmassService.OnStart()

	go ihs.executeAllSearches()
	return nil
}

func (ihs *IPHistoryService) OnStop() error {
	ihs.BaseAmassService.OnStop()
	return nil
}

func (ihs *IPHistoryService) executeAllSearches() {
	ihs.SetActive(true)
	// Loop over all the root domains provided in the config
	for _, domain := range ihs.Config().Domains {
		if !ihs.duplicate(domain) {
			ihs.LookupIPs(domain)
			time.Sleep(1 * time.Second)
		}
	}
	ihs.SetActive(false)
}

// Returns true if the domain is a duplicate entry in the filter.
// If not, the domain is added to the filter
func (ihs *IPHistoryService) duplicate(domain string) bool {
	ihs.Lock()
	defer ihs.Unlock()

	if _, found := ihs.filter[domain]; found {
		return true
	}
	ihs.filter[domain] = struct{}{}
	return false
}

// LookupIPs - Attempts to obtain IP addresses from a root domain name
func (ihs *IPHistoryService) LookupIPs(domain string) {
	// The ViewDNS IP History lookup sometimes reveals interesting results
	page := GetWebPage("http://viewdns.info/iphistory/?domain=" + domain)
	if page == "" {
		return
	}
	// Look for IP addresses in the web page returned
	var unique []string
	re := regexp.MustCompile(IPv4RE)
	for _, sd := range re.FindAllString(page, -1) {
		u := NewUniqueElements(unique, sd)

		if len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	// Each IP address could provide a netblock to investigate
	for _, ip := range unique {
		ihs.SendOut(&AmassRequest{
			Domain:  domain,
			Address: ip,
			Tag:     DNS,
			Source:  "IP History",
		})
	}
}
