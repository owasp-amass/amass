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

	go ihs.processRequests()
	return nil
}

func (ihs *IPHistoryService) OnStop() error {
	ihs.BaseAmassService.OnStop()
	return nil
}

func (ihs *IPHistoryService) sendOut(req *AmassRequest) {
	// Perform the channel write in a goroutine
	go func() {
		ihs.SetActive(true)
		ihs.Output() <- req
		ihs.SetActive(true)
	}()
}

func (ihs *IPHistoryService) processRequests() {
	max := time.NewTicker(1 * time.Second)
	defer max.Stop()

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ihs.Input():
			<-max.C
			go ihs.LookupIPs(req)
		case <-t.C:
			ihs.SetActive(false)
		case <-ihs.Quit():
			break loop
		}
	}
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
func (ihs *IPHistoryService) LookupIPs(req *AmassRequest) {
	ihs.SetActive(true)

	if ihs.duplicate(req.Domain) {
		return
	}
	// The ViewDNS IP History lookup sometimes reveals interesting results
	page := GetWebPage("http://viewdns.info/iphistory/?domain=" + req.Domain)
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
		ihs.sendOut(&AmassRequest{
			Domain:  req.Domain,
			Address: ip,
			Tag:     DNS,
			Source:  "IP History",
		})
	}
}
