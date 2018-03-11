// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"sort"
	"strconv"
	"strings"
	"time"
)

type SweepService struct {
	BaseAmassService
}

func NewSweepService(in, out chan *AmassRequest) *SweepService {
	ss := new(SweepService)

	ss.BaseAmassService = *NewBaseAmassService("Sweep Service", ss)

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

func (ss *SweepService) sendOut(req *AmassRequest) {
	ss.SetActive(true)
	ss.Output() <- req
}

func (ss *SweepService) processRequests() {
	filter := make(map[string]struct{})

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ss.Input():
			ss.SetActive(true)
			ss.AttemptSweep(req, filter)
		case <-t.C:
			ss.SetActive(false)
		case <-ss.Quit():
			break loop
		}
	}
}

// AttemptSweep - Initiates a sweep of a subset of the addresses within the CIDR
func (ss *SweepService) AttemptSweep(req *AmassRequest, filter map[string]struct{}) {
	var newIPs []string

	// Get the subset of nearby IP addresses
	ips := getCIDRSubset(hosts(req), req.Address, 200)
	for _, ip := range ips {
		if _, found := filter[ip]; !found {
			filter[ip] = struct{}{}
			newIPs = append(newIPs, ip)
		}
	}
	// Perform the reverse queries for all the new hosts
	for _, ip := range newIPs {
		go ss.sendOut(&AmassRequest{
			Domain:  req.Domain,
			Address: ip,
			Tag:     DNS,
			Source:  "DNS",
		})
	}
}

func hosts(req *AmassRequest) []string {
	ip := net.ParseIP(req.Address)

	var ips []string
	for ip := ip.Mask(req.Netblock.Mask); req.Netblock.Contains(ip); inc(ip) {
		ips = append(ips, ip.String())
	}
	// Remove network address and broadcast address
	return ips[1 : len(ips)-1]
}

func inc(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// getCIDRSubset - Returns a subset of the hosts slice with num elements around the addr element
func getCIDRSubset(ips []string, addr string, num int) []string {
	offset := num / 2

	// Closure determines whether an IP address is less than or greater than another
	f := func(i int) bool {
		p1 := strings.Split(addr, ".")
		p2 := strings.Split(ips[i], ".")

		for idx := 0; idx < len(p1); idx++ {
			n1, _ := strconv.Atoi(p1[idx])
			n2, _ := strconv.Atoi(p2[idx])

			if n2 < n1 {
				return false
			} else if n2 > n1 {
				return true
			}
		}
		return true
	}
	// Searches for the addr IP address in the hosts slice
	idx := sort.Search(len(ips), f)
	if idx < len(ips) && ips[idx] == addr {
		// Now we determine the hosts elements to be included in the new slice
		s := idx - offset
		if s < 0 {
			s = 0
		}

		e := idx + offset + 1
		if e > len(ips) {
			e = len(ips)
		}
		return ips[s:e]
	}
	// In the worst case, return the entire hosts slice
	return ips
}
