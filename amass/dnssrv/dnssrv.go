// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dnssrv

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
	"github.com/irfansharif/cfilter"
	"golang.org/x/sync/semaphore"
)

const (
	defaultNumOpenFiles int64 = 10000
)

type DNSService struct {
	core.BaseAmassService

	bus evbus.Bus

	// Ensures we do not resolve names more than once
	filter *cfilter.CFilter

	// Data collected about various subdomains
	subdomains map[string]map[int][]string

	// Enforces a maximum number of DNS queries sent at any given moment
	sem *semaphore.Weighted
}

func NewDNSService(config *core.AmassConfig, bus evbus.Bus) *DNSService {
	// Obtain the proper weight based on file resource limits
	weight := (GetFileLimit() / 10) * 9
	if weight <= 0 {
		weight = defaultNumOpenFiles
	}

	ds := &DNSService{
		bus:        bus,
		filter:     cfilter.New(),
		subdomains: make(map[string]map[int][]string),
		sem:        semaphore.NewWeighted(weight),
	}

	ds.BaseAmassService = *core.NewBaseAmassService("DNS Service", config, ds)
	return ds
}

func (ds *DNSService) OnStart() error {
	ds.BaseAmassService.OnStart()

	ds.bus.SubscribeAsync(core.DNSQUERY, ds.SendRequest, false)
	ds.bus.SubscribeAsync(core.DNSSWEEP, ds.ReverseDNSSweep, false)
	go ds.processRequests()
	return nil
}

func (ds *DNSService) OnPause() error {
	return nil
}

func (ds *DNSService) OnResume() error {
	return nil
}

func (ds *DNSService) OnStop() error {
	ds.BaseAmassService.OnStop()

	ds.bus.Unsubscribe(core.DNSQUERY, ds.SendRequest)
	ds.bus.Unsubscribe(core.DNSSWEEP, ds.ReverseDNSSweep)
	return nil
}

func (ds *DNSService) processRequests() {
	t := time.NewTicker(ds.Config().Frequency)
loop:
	for {
		select {
		case <-t.C:
			ds.performRequest()
		case <-ds.PauseChan():
			t.Stop()
		case <-ds.ResumeChan():
			t = time.NewTicker(ds.Config().Frequency)
		case <-ds.Quit():
			break loop
		}
	}
	t.Stop()
}

func (ds *DNSService) duplicate(name string) bool {
	if ds.filter.Lookup([]byte(name)) {
		return true
	}
	ds.filter.Insert([]byte(name))
	return false
}

func (ds *DNSService) performRequest() {
	req := ds.NextRequest()
	// Plow through the requests that are not of interest
	for req != nil && (req.Name == "" || req.Domain == "" ||
		ds.duplicate(req.Name) || ds.Config().Blacklisted(req.Name)) {
		req = ds.NextRequest()
	}
	if req == nil {
		return
	}

	ds.sem.Acquire(context.Background(), 6)
	ds.SetActive()
	go ds.completeQueries(req)
}

var InitialQueryTypes = []string{
	"TXT",
	"A",
	"AAAA",
	"CNAME",
}

func (ds *DNSService) completeQueries(req *core.AmassRequest) {
	defer ds.sem.Release(6)

	var answers []core.DNSAnswer
	for _, t := range InitialQueryTypes {
		a, err := Resolve(req.Name, t)
		if err == nil {
			answers = append(answers, a...)
			break
		}
		ds.Config().Log.Print(err)
		time.Sleep(ds.Config().Frequency)
	}

	req.Records = answers
	if len(req.Records) == 0 {
		return
	}
	if req.Tag != core.CERT && DetectWildcard(req.Domain, req.Name, req.Records) {
		return
	}
	// Make sure we know about any new subdomains
	ds.checkForNewSubdomain(req)
	ds.bus.Publish(core.RESOLVED, req)
}

func (ds *DNSService) checkForNewSubdomain(req *core.AmassRequest) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return
	}
	// Do not further evaluate service subdomains
	if labels[1] == "_tcp" || labels[1] == "_udp" || labels[1] == "_tls" {
		return
	}
	sub := strings.Join(labels[1:], ".")
	// Have we already seen this subdomain?
	if ds.dupSubdomain(sub) {
		return
	}
	// It cannot have fewer labels than the root domain name
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return
	}

	if !ds.Config().IsDomainInScope(req.Name) {
		return
	}
	// Does this subdomain have a wildcard?
	if DetectWildcard(req.Domain, req.Name, req.Records) {
		return
	}
	// Otherwise, run the basic queries against this name
	ds.basicQueries(sub, req.Domain)
	go ds.queryServiceNames(sub, req.Domain)
}

func (ds *DNSService) dupSubdomain(sub string) bool {
	ds.Lock()
	defer ds.Unlock()

	if _, found := ds.subdomains[sub]; found {
		return true
	}
	ds.subdomains[sub] = make(map[int][]string)
	return false
}

func (ds *DNSService) basicQueries(subdomain, domain string) {
	var answers []core.DNSAnswer

	// Obtain the DNS answers for the NS records related to the domain
	if ans, err := Resolve(subdomain, "NS"); err == nil {
		for _, a := range ans {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]

			if ds.Config().Active {
				go ds.attemptZoneXFR(domain, subdomain, a.Data)
			}
			answers = append(answers, a)
		}
	} else {
		ds.Config().Log.Printf("DNS NS record query error: %s: %v", subdomain, err)
	}
	// Obtain the DNS answers for the MX records related to the domain
	if ans, err := Resolve(subdomain, "MX"); err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	} else {
		ds.Config().Log.Printf("DNS MX record query error: %s: %v", subdomain, err)
	}
	// Obtain the DNS answers for the SOA records related to the domain
	if ans, err := Resolve(subdomain, "SOA"); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Config().Log.Printf("DNS SOA record query error: %s: %v", subdomain, err)
	}

	ds.bus.Publish(core.RESOLVED, &core.AmassRequest{
		Name:    subdomain,
		Domain:  domain,
		Records: answers,
		Tag:     "dns",
		Source:  "Forward DNS",
	})
}

func (ds *DNSService) attemptZoneXFR(domain, sub, server string) {
	if names, err := ZoneTransfer(domain, sub, server); err == nil {
		for _, name := range names {
			ds.SendRequest(&core.AmassRequest{
				Name:   name,
				Domain: domain,
				Tag:    "axfr",
				Source: "DNS ZoneXFR",
			})
		}
	} else {
		ds.Config().Log.Printf("DNS zone xfr failed: %s: %v", sub, err)
	}
}

func (ds *DNSService) queryServiceNames(subdomain, domain string) {
	// Check all the popular SRV records
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		if ds.duplicate(srvName) {
			continue
		}

		if a, err := Resolve(srvName, "SRV"); err == nil {
			ds.bus.Publish(core.RESOLVED, &core.AmassRequest{
				Name:    srvName,
				Domain:  domain,
				Records: a,
				Tag:     "dns",
				Source:  "Forward DNS",
			})
		}
		time.Sleep(ds.Config().Frequency)
	}
}

func (ds *DNSService) ReverseDNSSweep(domain, addr string, cidr *net.IPNet) {
	// Get the subset of 200 nearby IP addresses
	ips := utils.CIDRSubset(cidr, addr, 200)
	// Go through the IP addresses
	for _, ip := range ips {
		a := ip.String()

		if ds.duplicate(a) {
			continue
		}

		ptrName, answer, err := Reverse(a)
		if err == nil {
			ds.bus.Publish(core.RESOLVED, &core.AmassRequest{
				Name:   ptrName,
				Domain: domain,
				Records: []core.DNSAnswer{{
					Name: ptrName,
					Type: 12,
					TTL:  0,
					Data: answer,
				}},
				Tag:    "dns",
				Source: "Reverse DNS",
			})
		}
		time.Sleep(ds.Config().Frequency)
	}
}
