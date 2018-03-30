// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"time"
)

type ReverseDNSService struct {
	BaseAmassService

	queue []*AmassRequest

	// Ensures that the same IP is not sent out twice
	filter map[string]struct{}
}

func NewReverseDNSService(in, out chan *AmassRequest, config *AmassConfig) *ReverseDNSService {
	rds := &ReverseDNSService{filter: make(map[string]struct{})}

	rds.BaseAmassService = *NewBaseAmassService("Reverse DNS Service", config, rds)
	// Do not perform reverse lookups on localhost
	rds.filter["127.0.0.1"] = struct{}{}

	rds.input = in
	rds.output = out
	return rds
}

func (rds *ReverseDNSService) OnStart() error {
	rds.BaseAmassService.OnStart()

	go rds.processRequests()
	return nil
}

func (rds *ReverseDNSService) OnStop() error {
	rds.BaseAmassService.OnStop()
	return nil
}

func (rds *ReverseDNSService) processRequests() {
	t := time.NewTicker(rds.Config().Frequency)
	defer t.Stop()

	check := time.NewTicker(10 * time.Second)
	defer check.Stop()
loop:
	for {
		select {
		case req := <-rds.Input():
			<-t.C
			rds.SetActive(true)
			go rds.reverseDNS(req)
		case <-check.C:
			rds.SetActive(false)
		case <-rds.Quit():
			break loop
		}
	}
}

// Returns true if the IP is a duplicate entry in the filter.
// If not, the IP is added to the filter
func (rds *ReverseDNSService) duplicate(ip string) bool {
	rds.Lock()
	defer rds.Unlock()

	if _, found := rds.filter[ip]; found {
		return true
	}
	rds.filter[ip] = struct{}{}
	return false
}

// reverseDNS - Attempts to discover DNS names from an IP address using a reverse DNS
func (rds *ReverseDNSService) reverseDNS(req *AmassRequest) {
	if req.Address == "" || rds.duplicate(req.Address) {
		return
	}

	name, err := ReverseDNSWithDialContext(rds.Config().DNSDialContext, req.Address)
	if err != nil {
		return
	}

	re := AnySubdomainRegex()
	if re.MatchString(name) {
		// Send the name to be resolved in the forward direction
		rds.performOutput(&AmassRequest{
			Name:       name,
			Tag:        "dns",
			Source:     "Reverse DNS",
			addDomains: req.addDomains,
		})
	}
}

func (rds *ReverseDNSService) performOutput(req *AmassRequest) {
	config := rds.Config()

	if req.addDomains {
		req.Domain = config.domainLookup.SubdomainToDomain(req.Name)
		if req.Domain != "" {
			if config.AdditionalDomains {
				config.AddDomains([]string{req.Domain})
			}
			rds.SendOut(req)
		}
		return
	}
	// Check if the discovered name belongs to a root domain of interest
	for _, domain := range config.Domains() {
		re := SubdomainRegex(domain)
		re.Longest()

		// Once we have a match, the domain is added to the request
		if match := re.FindString(req.Name); match != "" {
			req.Name = match
			req.Domain = domain
			rds.SendOut(req)
			break
		}
	}
}
