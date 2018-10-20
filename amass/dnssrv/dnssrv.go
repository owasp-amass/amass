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
	// InitialQueryTypes include the DNS record types that are
	// initially requested for a discovered name
	InitialQueryTypes = []string{
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

// DNSService is the AmassService that handles all DNS name resolution requests within
// the architecture. This is achieved by receiving all the DNSQUERY and DNSSWEEP events.
type DNSService struct {
	core.BaseAmassService

	bus evbus.Bus

	// Ensures we do not resolve names more than once
	filter *cfilter.CFilter

	cidrBlacklist []*net.IPNet
}

// NewDNSService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewDNSService(config *core.AmassConfig, bus evbus.Bus) *DNSService {
	ds := &DNSService{
		bus:    bus,
		filter: cfilter.New(),
	}

	for _, n := range badSubnets {
		if _, ipnet, err := net.ParseCIDR(n); err == nil {
			ds.cidrBlacklist = append(ds.cidrBlacklist, ipnet)
		}
	}

	ds.BaseAmassService = *core.NewBaseAmassService("DNS Service", config, ds)
	return ds
}

// OnStart implements the AmassService interface
func (ds *DNSService) OnStart() error {
	ds.BaseAmassService.OnStart()

	ds.bus.SubscribeAsync(core.NEWSUB, ds.newSubdomain, false)
	ds.bus.SubscribeAsync(core.DNSQUERY, ds.addRequest, false)
	ds.bus.SubscribeAsync(core.DNSSWEEP, ds.reverseDNSSweep, false)
	go ds.processRequests()
	return nil
}

// OnPause implements the AmassService interface
func (ds *DNSService) OnPause() error {
	return nil
}

// OnResume implements the AmassService interface
func (ds *DNSService) OnResume() error {
	return nil
}

// OnStop implements the AmassService interface
func (ds *DNSService) OnStop() error {
	ds.BaseAmassService.OnStop()

	ds.bus.Unsubscribe(core.NEWSUB, ds.newSubdomain)
	ds.bus.Unsubscribe(core.DNSQUERY, ds.addRequest)
	ds.bus.Unsubscribe(core.DNSSWEEP, ds.reverseDNSSweep)
	return nil
}

func (ds *DNSService) addRequest(req *core.AmassRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}
	if ds.duplicate(req.Name) || ds.Config().Blacklisted(req.Name) {
		return
	}
	ds.SendRequest(req)
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
				continue
			}
			if req := ds.NextRequest(); req != nil {
				core.MaxConnections.Acquire(len(InitialQueryTypes))
				go ds.performRequest(req)
			} else {
				time.Sleep(100 * time.Millisecond)
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

func (ds *DNSService) performRequest(req *core.AmassRequest) {
	defer core.MaxConnections.Release(len(InitialQueryTypes))

	var answers []core.DNSAnswer

	ds.SetActive()
	for _, t := range InitialQueryTypes {
		if a, err := Resolve(req.Name, t); err == nil {
			if ds.goodDNSRecords(a) {
				answers = append(answers, a...)
			}
		} else {
			ds.Config().Log.Print(err)
		}
	}
	ds.SetActive()

	req.Records = answers
	if len(req.Records) == 0 {
		return
	}
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

func (ds *DNSService) newSubdomain(req *core.AmassRequest, times int) {
	if times != 1 || HasWildcard(req.Domain, req.Name) {
		return
	}

	ds.basicQueries(req.Name, req.Domain)
	go ds.queryServiceNames(req.Name, req.Domain)
}

func (ds *DNSService) basicQueries(subdomain, domain string) {
	var answers []core.DNSAnswer

	core.MaxConnections.Acquire(4)
	defer core.MaxConnections.Release(4)
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
	// Obtain the DNS answers for the SPF records related to the domain
	if ans, err := Resolve(subdomain, "SPF"); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Config().Log.Printf("DNS SPF record query error: %s: %v", subdomain, err)
	}

	if len(answers) > 0 {
		ds.bus.Publish(core.RESOLVED, &core.AmassRequest{
			Name:    subdomain,
			Domain:  domain,
			Records: answers,
			Tag:     core.DNS,
			Source:  "Forward DNS",
		})
	}
}

func (ds *DNSService) attemptZoneXFR(domain, sub, server string) {
	core.MaxConnections.Acquire(1)
	defer core.MaxConnections.Release(1)

	if names, err := ZoneTransfer(domain, sub, server); err == nil {
		for _, name := range names {
			ds.SendRequest(&core.AmassRequest{
				Name:   name,
				Domain: domain,
				Tag:    core.AXFR,
				Source: "DNS Zone XFR",
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

		core.MaxConnections.Acquire(1)
		if a, err := Resolve(srvName, "SRV"); err == nil {
			ds.bus.Publish(core.RESOLVED, &core.AmassRequest{
				Name:    srvName,
				Domain:  domain,
				Records: a,
				Tag:     core.DNS,
				Source:  "Forward DNS",
			})
		}
		core.MaxConnections.Release(1)
	}
}

func (ds *DNSService) reverseDNSSweep(addr string, cidr *net.IPNet) {
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

		core.MaxConnections.Acquire(1)
		go ds.reverseDNSRoutine(a)
	}
}

func (ds *DNSService) reverseDNSRoutine(ip string) {
	defer core.MaxConnections.Release(1)

	ds.SetActive()
	ptr, answer, err := Reverse(ip)
	if err != nil {
		return
	}

	if !ds.Config().IsDomainInScope(answer) {
		return
	}

	domain := ds.Config().WhichDomain(answer)
	if domain == "" {
		return
	}

	ds.bus.Publish(core.RESOLVED, &core.AmassRequest{
		Name:   ptr,
		Domain: domain,
		Records: []core.DNSAnswer{{
			Name: ptr,
			Type: 12,
			TTL:  0,
			Data: answer,
		}},
		Tag:    core.DNS,
		Source: "Reverse DNS",
	})
}
