// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dnssrv

import (
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
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
	Answers      []core.DNSAnswer
}

type wildcardRequest struct {
	Request      *core.AmassRequest
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

// DNSService is the AmassService that handles all DNS name resolution requests within
// the architecture. This is achieved by receiving all the DNSQUERY and DNSSWEEP events.
type DNSService struct {
	core.BaseAmassService

	bus evbus.Bus

	// Ensures we do not resolve names more than once
	filter *utils.StringFilter

	wildcards        map[string]*wildcard
	wildcardRequests chan wildcardRequest

	cidrBlacklist []*net.IPNet
}

// NewDNSService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewDNSService(config *core.AmassConfig, bus evbus.Bus) *DNSService {
	ds := &DNSService{
		bus:              bus,
		filter:           utils.NewStringFilter(),
		wildcards:        make(map[string]*wildcard),
		wildcardRequests: make(chan wildcardRequest),
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
	go ds.processWildcardRequests()
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
	if ds.filter.Duplicate(req.Name) || ds.Config().Blacklisted(req.Name) {
		ds.bus.Publish(core.RELEASEREQ)
		return
	}
	if !core.TrustedTag(req.Tag) && ds.GetWildcardType(req) == WildcardTypeDynamic {
		ds.bus.Publish(core.RELEASEREQ)
		return
	}
	ds.SendRequest(req)
}

func (ds *DNSService) sendResolved(req *core.AmassRequest) {
	if !core.TrustedTag(req.Tag) && ds.MatchesWildcard(req) {
		return
	}
	ds.bus.Publish(core.RESOLVED, req)
}

func (ds *DNSService) processRequests() {
	for {
		select {
		case <-ds.PauseChan():
			<-ds.ResumeChan()
		case <-ds.Quit():
			return
		case req := <-ds.RequestChan():
			core.MaxConnections.Acquire(len(InitialQueryTypes))
			go ds.performRequest(req)
		}
	}
}

func (ds *DNSService) performRequest(req *core.AmassRequest) {
	ds.bus.Publish(core.RELEASEREQ)
	defer core.MaxConnections.Release(len(InitialQueryTypes))

	ds.SetActive()
	var answers []core.DNSAnswer
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
			ds.Config().Log.Print(err)
		}
	}

	req.Records = answers
	if len(req.Records) == 0 {
		// Check if this unresolved name should be output by the enumeration
		if ds.Config().IncludeUnresolvable && ds.Config().IsDomainInScope(req.Name) {
			ds.bus.Publish(core.OUTPUT, &core.AmassOutput{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}
	go ds.sendResolved(req)
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
	if times != 1 {
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
				go ds.attemptZoneXFR(subdomain, domain, a.Data)
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
		ds.sendResolved(&core.AmassRequest{
			Name:    subdomain,
			Domain:  domain,
			Records: answers,
			Tag:     core.DNS,
			Source:  "Forward DNS",
		})
	}
}

func (ds *DNSService) attemptZoneXFR(sub, domain, server string) {
	core.MaxConnections.Acquire(1)
	defer core.MaxConnections.Release(1)

	if names, err := ZoneTransfer(sub, domain, server); err == nil {
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

		if ds.filter.Duplicate(srvName) {
			continue
		}

		core.MaxConnections.Acquire(1)
		if a, err := Resolve(srvName, "SRV"); err == nil {
			ds.sendResolved(&core.AmassRequest{
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
	domain := ds.Config().WhichDomain(answer)
	if domain == "" {
		return
	}
	ds.sendResolved(&core.AmassRequest{
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

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (ds *DNSService) MatchesWildcard(req *core.AmassRequest) bool {
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
func (ds *DNSService) GetWildcardType(req *core.AmassRequest) int {
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
			r.WildcardType <- ds.performWildcardRequest(r.Request)
		}
	}
}

func (ds *DNSService) performWildcardRequest(req *core.AmassRequest) int {
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
		set := make([][]core.DNSAnswer, numOfWildcardTests)
		for i := 0; i < numOfWildcardTests; i++ {
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
			ds.Config().Log.Printf("%s has a static DNS wildcard", sub)
		} else {
			entry.WildcardType = WildcardTypeDynamic
			ds.Config().Log.Printf("%s has a dynamic DNS wildcard", sub)
		}
	}
	return entry
}

func (ds *DNSService) compareAnswers(ans1, ans2 []core.DNSAnswer) bool {
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

func (ds *DNSService) wildcardTestResults(sub string) []core.DNSAnswer {
	var answers []core.DNSAnswer

	name := UnlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	core.MaxConnections.Acquire(3)
	if a, err := Resolve(name, "CNAME"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "A"); err == nil {
		answers = append(answers, a...)
	}
	if a, err := Resolve(name, "AAAA"); err == nil {
		answers = append(answers, a...)
	}
	core.MaxConnections.Release(3)

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
