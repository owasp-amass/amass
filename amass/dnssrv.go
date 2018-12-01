// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/utils"
	"github.com/miekg/dns"
)

const (
	numOfWildcardTests = 5

	maxDNSNameLen  = 253
	maxDNSLabelLen = 63
	maxLabelLen    = 24

	// The hyphen has been removed
	ldhChars = "abcdefghijklmnopqrstuvwxyz0123456789"
)

// Names for the different types of wildcards that can be detected.
const (
	WildcardTypeNone = iota
	WildcardTypeStatic
	WildcardTypeDynamic
)

type wildcard struct {
	WildcardType int
	Answers      []DNSAnswer
}

type wildcardRequest struct {
	Request      *Request
	WildcardType chan int
}

var (
	// InitialQueryTypes include the DNS record types that are
	// initially requested for a discovered name
	InitialQueryTypes = []string{
		"TXT",
		"CNAME",
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
// the architecture. This is achieved by receiving all the DNSQUERY and DNSSWEEP events.
type DNSService struct {
	BaseService

	filter           *utils.StringFilter
	wildcards        map[string]*wildcard
	wildcardRequests chan wildcardRequest
	cidrBlacklist    []*net.IPNet
}

// NewDNSService returns he object initialized, but not yet started.
func NewDNSService(e *Enumeration) *DNSService {
	ds := &DNSService{
		filter:           utils.NewStringFilter(),
		wildcards:        make(map[string]*wildcard),
		wildcardRequests: make(chan wildcardRequest),
	}

	for _, n := range badSubnets {
		if _, ipnet, err := net.ParseCIDR(n); err == nil {
			ds.cidrBlacklist = append(ds.cidrBlacklist, ipnet)
		}
	}

	ds.BaseService = *NewBaseService(e, "DNS Service", ds)
	return ds
}

// OnStart implements the Service interface
func (ds DNSService) OnStart() error {
	ds.BaseService.OnStart()

	go ds.processRequests()
	go ds.processWildcardRequests()

	for _, domain := range ds.Enum().Config.Domains() {
		go ds.basicQueries(domain, domain)
	}
	return nil
}

func (ds *DNSService) processRequests() {
	for {
		select {
		case <-ds.PauseChan():
			<-ds.ResumeChan()
		case <-ds.Quit():
			return
		case req := <-ds.RequestChan():
			go ds.performRequest(req)
		}
	}
}

func (ds *DNSService) performRequest(req *Request) {
	defer ds.Enum().MaxFlow.Release(1)

	ds.SetActive()
	MaxConnections.Acquire(len(InitialQueryTypes))
	defer MaxConnections.Release(len(InitialQueryTypes))

	var answers []DNSAnswer
	for _, t := range InitialQueryTypes {
		if a, err := Resolve(req.Name, t); err == nil {
			if ds.goodDNSRecords(a) {
				answers = append(answers, a...)
			}
			// Do not continue if a CNAME was discovered
			if t == "CNAME" {
				break
			}
		} else {
			ds.Enum().Log.Printf("DNS: %v", err)
		}
		ds.SetActive()
	}

	req.Records = answers
	if len(req.Records) == 0 {
		// Check if this unresolved name should be output by the enumeration
		if ds.Enum().Config.IncludeUnresolvable && ds.Enum().Config.IsDomainInScope(req.Name) {
			ds.Enum().OutputEvent(&Output{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}

	ds.SetActive()
	ds.Enum().ResolvedNameEvent(req)
}

func (ds *DNSService) goodDNSRecords(records []DNSAnswer) bool {
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

// NewSubdomain is called by the Name Service when proper subdomains are discovered.
func (ds *DNSService) NewSubdomain(req *Request, times int) {
	if times != 1 {
		return
	}
	ds.SetActive()
	ds.basicQueries(req.Name, req.Domain)
	go ds.queryServiceNames(req.Name, req.Domain)
}

func (ds *DNSService) basicQueries(subdomain, domain string) {
	var answers []DNSAnswer

	MaxConnections.Acquire(4)
	defer MaxConnections.Release(4)

	ds.SetActive()
	// Obtain the DNS answers for the NS records related to the domain
	if ans, err := Resolve(subdomain, "NS"); err == nil {
		for _, a := range ans {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]

			if ds.Enum().Config.Active {
				go ds.attemptZoneXFR(subdomain, domain, a.Data)
			}
			answers = append(answers, a)
		}
	} else {
		ds.Enum().Log.Printf("DNS: NS record query error: %s: %v", subdomain, err)
	}

	ds.SetActive()
	// Obtain the DNS answers for the MX records related to the domain
	if ans, err := Resolve(subdomain, "MX"); err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	} else {
		ds.Enum().Log.Printf("DNS: MX record query error: %s: %v", subdomain, err)
	}

	ds.SetActive()
	// Obtain the DNS answers for the SOA records related to the domain
	if ans, err := Resolve(subdomain, "SOA"); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Enum().Log.Printf("DNS: SOA record query error: %s: %v", subdomain, err)
	}

	ds.SetActive()
	// Obtain the DNS answers for the SPF records related to the domain
	if ans, err := Resolve(subdomain, "SPF"); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Enum().Log.Printf("DNS: SPF record query error: %s: %v", subdomain, err)
	}

	if len(answers) > 0 {
		ds.SetActive()
		ds.Enum().ResolvedNameEvent(&Request{
			Name:    subdomain,
			Domain:  domain,
			Records: answers,
			Tag:     DNS,
			Source:  "Forward DNS",
		})
	}
}

func (ds *DNSService) attemptZoneXFR(sub, domain, server string) {
	if ds.filter.Duplicate(sub + server) {
		return
	}

	MaxConnections.Acquire(1)
	defer MaxConnections.Release(1)

	if requests, err := ZoneTransfer(sub, domain, server); err == nil {
		for _, req := range requests {
			ds.Enum().ResolvedNameEvent(req)
		}
	} else {
		ds.Enum().Log.Printf("DNS: Zone XFR failed: %s: %v", sub, err)
	}
}

func (ds *DNSService) queryServiceNames(subdomain, domain string) {
	ds.SetActive()
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		if ds.filter.Duplicate(srvName) {
			continue
		}

		MaxConnections.Acquire(1)
		if a, err := Resolve(srvName, "SRV"); err == nil {
			ds.Enum().ResolvedNameEvent(&Request{
				Name:    srvName,
				Domain:  domain,
				Records: a,
				Tag:     DNS,
				Source:  "Forward DNS",
			})
		}
		MaxConnections.Release(1)
		ds.SetActive()
	}
}

// ReverseDNSSweep is called by the Address Service to perform sweeps across an address range.
func (ds *DNSService) ReverseDNSSweep(addr string, cidr *net.IPNet) {
	var ips []net.IP

	// Get information about nearby IP addresses
	if ds.Enum().Config.Active {
		ips = utils.CIDRSubset(cidr, addr, 500)
	} else {
		ips = utils.CIDRSubset(cidr, addr, 250)
	}

	for _, ip := range ips {
		a := ip.String()
		if ds.filter.Duplicate(a) {
			continue
		}
		MaxConnections.Acquire(1)
		ds.Enum().MaxFlow.Acquire(1)
		go ds.reverseDNSRoutine(a)
	}
}

func (ds *DNSService) reverseDNSRoutine(ip string) {
	defer ds.Enum().MaxFlow.Release(1)
	defer MaxConnections.Release(1)

	ds.SetActive()
	ptr, answer, err := Reverse(ip)
	if err != nil {
		return
	}
	// Check that the name discovered is in scope
	domain := ds.Enum().Config.WhichDomain(answer)
	if domain == "" {
		return
	}
	ds.Enum().ResolvedNameEvent(&Request{
		Name:   ptr,
		Domain: domain,
		Records: []DNSAnswer{{
			Name: ptr,
			Type: 12,
			TTL:  0,
			Data: answer,
		}},
		Tag:    DNS,
		Source: "Reverse DNS",
	})
	ds.SetActive()
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (ds *DNSService) MatchesWildcard(req *Request) bool {
	res := make(chan int)

	ds.wildcardRequests <- wildcardRequest{
		Request:      req,
		WildcardType: res,
	}
	if WildcardTypeNone == <-res {
		return false
	}
	return true
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (ds *DNSService) GetWildcardType(req *Request) int {
	res := make(chan int)

	ds.wildcardRequests <- wildcardRequest{
		Request:      req,
		WildcardType: res,
	}
	return <-res
}

func (ds *DNSService) processWildcardRequests() {
	for {
		select {
		case <-ds.Quit():
			return
		case r := <-ds.wildcardRequests:
			ds.SetActive()
			r.WildcardType <- ds.performWildcardRequest(r.Request)
		}
	}
}

func (ds *DNSService) performWildcardRequest(req *Request) int {
	base := len(strings.Split(req.Domain, "."))
	labels := strings.Split(req.Name, ".")

	for i := len(labels) - base; i > 0; i-- {
		sub := strings.Join(labels[i:], ".")
		w := ds.getWildcard(sub)

		if w.WildcardType == WildcardTypeDynamic {
			return WildcardTypeDynamic
		} else if w.WildcardType == WildcardTypeStatic {
			if len(req.Records) == 0 {
				return WildcardTypeStatic
			} else if ds.compareAnswers(req.Records, w.Answers) {
				return WildcardTypeStatic
			}
		}
	}
	return WildcardTypeNone
}

func (ds *DNSService) getWildcard(sub string) *wildcard {
	entry, found := ds.wildcards[sub]
	if !found {
		entry = &wildcard{
			WildcardType: WildcardTypeNone,
			Answers:      nil,
		}
		ds.wildcards[sub] = entry
		// Query multiple times with unlikely names against this subdomain
		set := make([][]DNSAnswer, numOfWildcardTests)
		for i := 0; i < numOfWildcardTests; i++ {
			ds.SetActive()
			a := ds.wildcardTestResults(sub)
			if a == nil {
				// There is no DNS wildcard
				return entry
			}
			set[i] = a
			time.Sleep(time.Second)
		}
		// Check if we have a static DNS wildcard
		match := true
		for i := 0; i < numOfWildcardTests-1; i++ {
			if !ds.compareAnswers(set[i], set[i+1]) {
				match = false
				break
			}
		}
		if match {
			entry.WildcardType = WildcardTypeStatic
			entry.Answers = set[0]
			ds.Enum().Log.Printf("%s has a static DNS wildcard", sub)
		} else {
			entry.WildcardType = WildcardTypeDynamic
			ds.Enum().Log.Printf("%s has a dynamic DNS wildcard", sub)
		}
	}
	return entry
}

func (ds *DNSService) compareAnswers(ans1, ans2 []DNSAnswer) bool {
	var match bool
loop:
	for _, a1 := range ans1 {
		for _, a2 := range ans2 {
			if strings.EqualFold(a1.Data, a2.Data) {
				match = true
				break loop
			}
		}
	}
	return match
}

func (ds *DNSService) wildcardTestResults(sub string) []DNSAnswer {
	var answers []DNSAnswer

	name := UnlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	MaxConnections.Acquire(3)
	if a, err := Resolve(name, "CNAME"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "A"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "AAAA"); err == nil {
		answers = append(answers, a...)
	}
	MaxConnections.Release(3)

	if len(answers) == 0 {
		return nil
	}
	return answers
}

// UnlikelyName takes a subdomain name and returns an unlikely DNS name within that subdomain
func UnlikelyName(sub string) string {
	var newlabel string
	ldh := []rune(ldhChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := maxDNSNameLen - (len(sub) + 1)
	if l > maxLabelLen {
		l = maxLabelLen
	} else if l < 1 {
		return ""
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

	l = (rand.Int() % l) + 1
	for i := 0; i < l; i++ {
		sel := rand.Int() % ldhLen

		// The first nor last char may be a hyphen
		if (i == 0 || i == l-1) && ldh[sel] == '-' {
			continue
		}
		newlabel = newlabel + string(ldh[sel])
	}

	if newlabel == "" {
		return newlabel
	}
	return newlabel + "." + sub
}
