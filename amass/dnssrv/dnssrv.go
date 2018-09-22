// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dnssrv

import (
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
	"github.com/irfansharif/cfilter"
	"github.com/miekg/dns"
)

var (
	InitialQueryTypesLen int64 = 4
	InitialQueryTypes          = []string{
		"TXT",
		"A",
		"AAAA",
		"CNAME",
	}

	badSubnets = []string{
		"198.105.244.0/24",
		"198.105.254.0/24",
		"88.204.137.0/24",
	}
)

type DNSService struct {
	core.BaseAmassService

	bus evbus.Bus

	// Ensures we do not resolve names more than once
	filter *cfilter.CFilter

	// Data collected about various subdomains
	subdomains map[string]map[int][]string

	cidrBlacklist []*net.IPNet
}

func NewDNSService(config *core.AmassConfig, bus evbus.Bus) *DNSService {
	ds := &DNSService{
		bus:        bus,
		filter:     cfilter.New(),
		subdomains: make(map[string]map[int][]string),
	}

	for _, n := range badSubnets {
		if _, ipnet, err := net.ParseCIDR(n); err == nil {
			ds.cidrBlacklist = append(ds.cidrBlacklist, ipnet)
		}
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
	var paused bool

	for {
		select {
		case <-ds.PauseChan():
			paused = true
		case <-ds.ResumeChan():
			paused = false
		case <-ds.Quit():
			return
		default:
			if paused {
				time.Sleep(time.Second)
			} else {
				ds.performRequest()
				time.Sleep(time.Millisecond)
			}
		}
	}
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
	go ds.completeQueries(req)
}

func (ds *DNSService) completeQueries(req *core.AmassRequest) {
	var answers []core.DNSAnswer

	ds.SetActive()
	for _, t := range InitialQueryTypes {
		a, err := Resolve(req.Name, t)
		if err == nil {
			if ds.goodDNSRecords(a) {
				answers = append(answers, a...)
			}
		} else {
			ds.Config().Log.Print(err)
		}
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

func (ds *DNSService) goodDNSRecords(records []core.DNSAnswer) bool {
	for _, r := range records {
		if r.Type != int(dns.TypeA) {
			continue
		}

		for _, cidr := range ds.cidrBlacklist {
			if cidr.Contains(net.ParseIP(r.Data)) {
				return false
			}
		}
	}
	return true
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
	}
}

func (ds *DNSService) ReverseDNSSweep(domain, addr string, cidr *net.IPNet) {
	var ips []net.IP

	// Get a subset of nearby IP addresses
	if ds.Config().Active {
		ips = utils.CIDRSubset(cidr, addr, 500)
	} else {
		ips = utils.CIDRSubset(cidr, addr, 100)
	}

	for _, ip := range ips {
		a := ip.String()

		if ds.duplicate(a) {
			continue
		}

		if ptrName, answer, err := Reverse(a); err == nil {
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
	}
}
