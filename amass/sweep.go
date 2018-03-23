// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"time"
)

type SweepService struct {
	BaseAmassService

	// Ensures that the same IP is not sent out twice
	filter map[string]struct{}
}

func NewSweepService(in, out chan *AmassRequest, config *AmassConfig) *SweepService {
	ss := &SweepService{filter: make(map[string]struct{})}

	ss.BaseAmassService = *NewBaseAmassService("Sweep Service", config, ss)

	ss.input = in
	ss.output = out
	return ss
}

func (ss *SweepService) OnStart() error {
	ss.BaseAmassService.OnStart()

	go ss.processRequests()
	return nil
}

func (ss *SweepService) OnStop() error {
	ss.BaseAmassService.OnStop()
	return nil
}

func (ss *SweepService) processRequests() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ss.Input():
			go ss.AttemptSweep(req)
		case <-t.C:
			ss.SetActive(false)
		case <-ss.Quit():
			break loop
		}
	}
}

// Returns true if the IP is a duplicate entry in the filter.
// If not, the IP is added to the filter
func (ss *SweepService) duplicate(ip string) bool {
	ss.Lock()
	defer ss.Unlock()

	if _, found := ss.filter[ip]; found {
		return true
	}
	ss.filter[ip] = struct{}{}
	return false
}

// AttemptSweep - Initiates a sweep of a subset of the addresses within the CIDR
func (ss *SweepService) AttemptSweep(req *AmassRequest) {
	var ips []string

	ss.SetActive(true)
	if req.Address != "" {
		// Get the subset of 200 nearby IP addresses
		ips = CIDRSubset(req.Netblock, req.Address, 200)
	} else if req.addDomains {
		ips = NetHosts(req.Netblock)
	}
	// Go through the IP addresses
	for _, ip := range ips {
		if !ss.duplicate(ip) {
			// Perform the reverse queries for all the new hosts
			ss.SendOut(&AmassRequest{
				Domain:     req.Domain,
				Address:    ip,
				Tag:        "dns",
				Source:     "DNS",
				addDomains: req.addDomains,
			})
		}
	}
}
