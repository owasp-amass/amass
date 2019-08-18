// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	sf "github.com/OWASP/Amass/stringfilter"
	"github.com/OWASP/Amass/utils"
	"github.com/miekg/dns"
)

var (
	// InitialQueryTypes include the DNS record types that are
	// initially requested for a discovered name
	InitialQueryTypes = []string{
		"CNAME",
		"TXT",
		"A",
		"AAAA",
	}

	badSubnets = []string{
		"198.105.244.0/24",
		"198.105.254.0/24",
		"88.204.137.0/24",
	}
)

// DNSService is the Service that handles all DNS name resolution requests within
// the architecture.
type DNSService struct {
	BaseService

	metrics    *MetricsCollector
	totalLock  sync.RWMutex
	totalNames int

	filter        *sf.StringFilter
	cidrBlacklist []*net.IPNet
}

// NewDNSService returns he object initialized, but not yet started.
func NewDNSService(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *DNSService {
	ds := &DNSService{filter: sf.NewStringFilter()}

	for _, n := range badSubnets {
		if _, ipnet, err := net.ParseCIDR(n); err == nil {
			ds.cidrBlacklist = append(ds.cidrBlacklist, ipnet)
		}
	}

	ds.BaseService = *NewBaseService(ds, "DNS Service", cfg, bus, pool)
	return ds
}

// OnStart implements the Service interface
func (ds *DNSService) OnStart() error {
	ds.BaseService.OnStart()

	ds.metrics = NewMetricsCollector(ds)
	ds.metrics.NamesRemainingCallback(ds.namesRemaining)

	ds.Bus().Subscribe(requests.ResolveNameTopic, ds.SendDNSRequest)
	ds.Bus().Subscribe(requests.ReverseSweepTopic, ds.dnsSweep)
	ds.Bus().Subscribe(requests.NewSubdomainTopic, ds.newSubdomain)
	go ds.processRequests()
	return nil
}

// OnStop implements the Service interface.
func (ds *DNSService) OnStop() error {
	ds.metrics.Stop()
	return nil
}

func (ds *DNSService) resolvedName(req *requests.DNSRequest) {
	if !requests.TrustedTag(req.Tag) && ds.Pool().MatchesWildcard(req) {
		return
	}
	// Check if this passes the enumeration network contraints
	var records []requests.DNSAnswer
	for _, ans := range req.Records {
		if ans.Type == 1 || ans.Type == 28 {
			if !ds.Config().IsAddressInScope(ans.Data) {
				continue
			}
		}
		records = append(records, ans)
	}
	if len(records) == 0 {
		return
	}
	req.Records = records

	ds.Bus().Publish(requests.NameResolvedTopic, req)
}

func (ds *DNSService) processRequests() {
	for {
		select {
		case <-ds.PauseChan():
			<-ds.ResumeChan()
		case <-ds.Quit():
			return
		case req := <-ds.DNSRequestChan():
			ds.Config().SemMaxDNSQueries.Acquire(1)
			go ds.performDNSRequest(req)
		case <-ds.AddrRequestChan():
		case <-ds.ASNRequestChan():
		case <-ds.WhoisRequestChan():
		}
	}
}

// Stats implements the Service interface
func (ds *DNSService) Stats() *ServiceStats {
	return ds.metrics.Stats()
}

func (ds *DNSService) namesRemaining() int {
	ds.totalLock.RLock()
	defer ds.totalLock.RUnlock()

	rlen := ds.DNSRequestLen()
	if rlen > 0 {
		rlen += ServiceRequestChanLength
	}
	return ds.totalNames + rlen
}

func (ds *DNSService) incTotalNames() {
	ds.totalLock.Lock()
	defer ds.totalLock.Unlock()

	ds.totalNames++
}

func (ds *DNSService) decTotalNames() {
	ds.totalLock.Lock()
	defer ds.totalLock.Unlock()

	ds.totalNames--
}

func (ds *DNSService) performDNSRequest(req *requests.DNSRequest) {
	ds.incTotalNames()
	defer ds.Config().SemMaxDNSQueries.Release(1)
	defer ds.decTotalNames()

	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	ds.SetActive()
	if ds.Config().Blacklisted(req.Name) || (!requests.TrustedTag(req.Tag) &&
		ds.Pool().GetWildcardType(req) == resolvers.WildcardTypeDynamic) {
		return
	}

	ds.SetActive()
	var answers []requests.DNSAnswer
	for _, t := range InitialQueryTypes {
		if a, err := ds.Pool().Resolve(req.Name, t, resolvers.PriorityLow); err == nil {
			if ds.goodDNSRecords(a) {
				answers = append(answers, a...)
			}
			// Do not continue if a CNAME was discovered
			if t == "CNAME" {
				ds.metrics.QueryTime(time.Now())
				break
			}
		} else {
			ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: %v", err))
		}
		ds.metrics.QueryTime(time.Now())
		ds.SetActive()
	}

	req.Records = answers
	if len(req.Records) == 0 {
		// Check if this unresolved name should be output by the enumeration
		if ds.Config().IncludeUnresolvable && ds.Config().IsDomainInScope(req.Name) {
			ds.Bus().Publish(requests.OutputTopic, &requests.Output{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}
	ds.resolvedName(req)
}

func (ds *DNSService) goodDNSRecords(records []requests.DNSAnswer) bool {
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

func (ds *DNSService) newSubdomain(req *requests.DNSRequest, times int) {
	if req != nil && times == 1 {
		go ds.processSubdomain(req)
	}
}

func (ds *DNSService) processSubdomain(req *requests.DNSRequest) {
	ds.basicQueries(req.Name, req.Domain)
	ds.queryServiceNames(req.Name, req.Domain)
}

func (ds *DNSService) basicQueries(subdomain, domain string) {
	ds.incTotalNames()
	defer ds.decTotalNames()

	ds.SetActive()
	var answers []requests.DNSAnswer
	// Obtain the DNS answers for the NS records related to the domain
	if ans, err := ds.Pool().Resolve(subdomain, "NS", resolvers.PriorityHigh); err == nil {
		for _, a := range ans {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]

			if ds.Config().Active {
				go ds.attemptZoneXFR(subdomain, domain, a.Data)
				//go ds.attemptZoneWalk(domain, a.Data)
			}
			answers = append(answers, a)
		}
	} else {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: NS record query error: %s: %v", subdomain, err))
	}
	ds.metrics.QueryTime(time.Now())

	ds.SetActive()
	// Obtain the DNS answers for the MX records related to the domain
	if ans, err := ds.Pool().Resolve(subdomain, "MX", resolvers.PriorityHigh); err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	} else {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: MX record query error: %s: %v", subdomain, err))
	}
	ds.metrics.QueryTime(time.Now())

	ds.SetActive()
	// Obtain the DNS answers for the SOA records related to the domain
	if ans, err := ds.Pool().Resolve(subdomain, "SOA", resolvers.PriorityHigh); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: SOA record query error: %s: %v", subdomain, err))
	}
	ds.metrics.QueryTime(time.Now())

	ds.SetActive()
	// Obtain the DNS answers for the SPF records related to the domain
	if ans, err := ds.Pool().Resolve(subdomain, "SPF", resolvers.PriorityHigh); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: SPF record query error: %s: %v", subdomain, err))
	}
	ds.metrics.QueryTime(time.Now())

	if len(answers) > 0 {
		ds.SetActive()
		ds.resolvedName(&requests.DNSRequest{
			Name:    subdomain,
			Domain:  domain,
			Records: answers,
			Tag:     requests.DNS,
			Source:  "Forward DNS",
		})
	}
}

func (ds *DNSService) attemptZoneXFR(sub, domain, server string) {
	if ds.filter.Duplicate(sub + server) {
		return
	}

	addr, err := ds.nameserverAddr(server)
	if addr == "" {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone XFR failed: %v", err))
		return
	}

	reqs, err := resolvers.ZoneTransfer(sub, domain, addr)
	if err != nil {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone XFR failed: %s: %v", server, err))
		return
	}

	for _, req := range reqs {
		ds.resolvedName(req)
	}
}

func (ds *DNSService) attemptZoneWalk(domain, server string) {
	addr, err := ds.nameserverAddr(server)
	if addr == "" {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone Walk failed: %v", err))
		return
	}

	reqs, err := resolvers.NsecTraversal(domain, addr)
	if err != nil {
		ds.Bus().Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone Walk failed: %s: %v", server, err))
		return
	}

	for _, req := range reqs {
		ds.SendDNSRequest(req)
	}
}

func (ds *DNSService) nameserverAddr(server string) (string, error) {
	a, err := ds.Pool().Resolve(server, "A", resolvers.PriorityHigh)
	if err != nil {
		a, err = ds.Pool().Resolve(server, "AAAA", resolvers.PriorityHigh)
		if err != nil {
			return "", fmt.Errorf("DNS server has no A or AAAA record: %s: %v", server, err)
		}
	}
	return a[0].Data, nil
}

func (ds *DNSService) queryServiceNames(subdomain, domain string) {
	ds.SetActive()
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		if ds.filter.Duplicate(srvName) {
			continue
		}
		ds.incTotalNames()
		if a, err := ds.Pool().Resolve(srvName, "SRV", resolvers.PriorityLow); err == nil {
			ds.resolvedName(&requests.DNSRequest{
				Name:    srvName,
				Domain:  domain,
				Records: a,
				Tag:     requests.DNS,
				Source:  "Forward DNS",
			})
		}
		ds.metrics.QueryTime(time.Now())
		ds.SetActive()
		ds.decTotalNames()
	}
}

func (ds *DNSService) dnsSweep(addr string, cidr *net.IPNet) {
	go ds.reverseDNSSweep(addr, cidr)
}

func (ds *DNSService) reverseDNSSweep(addr string, cidr *net.IPNet) {
	var ips []net.IP

	// Get information about nearby IP addresses
	if ds.Config().Active {
		ips = utils.CIDRSubset(cidr, addr, 500)
	} else {
		ips = utils.CIDRSubset(cidr, addr, 250)
	}

	for _, ip := range ips {
		a := ip.String()
		if ds.filter.Duplicate(a) {
			continue
		}
		ds.Config().SemMaxDNSQueries.Acquire(1)
		ds.reverseDNSQuery(a)
	}
}

func (ds *DNSService) reverseDNSQuery(ip string) {
	ds.incTotalNames()
	defer ds.decTotalNames()
	defer ds.Config().SemMaxDNSQueries.Release(1)

	ds.SetActive()
	ptr, answer, err := ds.Pool().ReverseDNS(ip)
	ds.metrics.QueryTime(time.Now())
	if err != nil {
		return
	}
	// Check that the name discovered is in scope
	domain := ds.Config().WhichDomain(answer)
	if domain == "" {
		return
	}

	ds.SetActive()
	ds.resolvedName(&requests.DNSRequest{
		Name:   ptr,
		Domain: domain,
		Records: []requests.DNSAnswer{{
			Name: ptr,
			Type: 12,
			TTL:  0,
			Data: answer,
		}},
		Tag:    requests.DNS,
		Source: "Reverse DNS",
	})
}
