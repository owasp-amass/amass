// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
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
	Answers      []core.DNSAnswer
}

type wildcardRequest struct {
	Request      *core.Request
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
	core.BaseService

	queries          *utils.Queue
	filter           *utils.StringFilter
	wildcards        map[string]*wildcard
	wildcardRequests chan wildcardRequest
	cidrBlacklist    []*net.IPNet
}

// NewDNSService returns he object initialized, but not yet started.
func NewDNSService(config *core.Config, bus *core.EventBus) *DNSService {
	ds := &DNSService{
		queries:          utils.NewQueue(),
		filter:           utils.NewStringFilter(),
		wildcards:        make(map[string]*wildcard),
		wildcardRequests: make(chan wildcardRequest),
	}

	for _, n := range badSubnets {
		if _, ipnet, err := net.ParseCIDR(n); err == nil {
			ds.cidrBlacklist = append(ds.cidrBlacklist, ipnet)
		}
	}

	ds.BaseService = *core.NewBaseService(ds, "DNS Service", config, bus)
	return ds
}

// OnStart implements the Service interface
func (ds *DNSService) OnStart() error {
	ds.BaseService.OnStart()

	ds.Bus().Subscribe(core.ResolveNameTopic, ds.SendRequest)
	ds.Bus().Subscribe(core.ReverseSweepTopic, ds.dnsSweep)
	ds.Bus().Subscribe(core.NewSubdomainTopic, ds.newSubdomain)
	go ds.processRequests()
	go ds.processMetrics()
	go ds.processWildcardRequests()

	for _, domain := range ds.Config().Domains() {
		go ds.basicQueries(domain, domain)
	}
	return nil
}

func (ds *DNSService) resolvedName(req *core.Request) {
	if !TrustedTag(req.Tag) && ds.MatchesWildcard(req) {
		return
	}
	ds.Bus().Publish(core.NameResolvedTopic, req)
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

func (ds *DNSService) processMetrics() {
	var perSec []int

	last := time.Now()
	t := time.NewTicker(time.Second)
	defer t.Stop()
	logTick := time.NewTicker(time.Minute)
	defer logTick.Stop()

	for {
		select {
		case <-ds.PauseChan():
			<-ds.ResumeChan()
		case <-ds.Quit():
			return
		case <-t.C:
			perSec = append(perSec, ds.queriesPerSec(last))
			last = time.Now()
		case <-logTick.C:
			ds.logAvgQueriesPerSec(perSec)
			perSec = []int{}
		}
	}
}

func (ds *DNSService) sendQueryTime(t time.Time) {
	ds.queries.Append(t)
}

func (ds *DNSService) queriesPerSec(last time.Time) int {
	var num int
	for {
		element, ok := ds.queries.Next()
		if !ok {
			break
		}
		comTime := element.(time.Time)
		if comTime.After(last) {
			num++
		}
	}
	return num
}

func (ds *DNSService) logAvgQueriesPerSec(perSec []int) {
	var total int
	for _, s := range perSec {
		total += s
	}
	if num := len(perSec); num > 0 {
		ds.Config().Log.Printf("Average DNS queries performed: %d/sec", total/num)
	}
}

func (ds *DNSService) performRequest(req *core.Request) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	ds.SetActive()
	if ds.Config().Blacklisted(req.Name) || (!TrustedTag(req.Tag) &&
		ds.GetWildcardType(req) == WildcardTypeDynamic) {
		return
	}

	var answers []core.DNSAnswer
	for _, t := range InitialQueryTypes {
		ds.sendQueryTime(time.Now())
		if a, err := Resolve(req.Name, t); err == nil {
			if ds.goodDNSRecords(a) {
				answers = append(answers, a...)
			}
			// Do not continue if a CNAME was discovered
			if t == "CNAME" {
				break
			}
		} else {
			ds.Config().Log.Printf("DNS: %v", err)
		}
		ds.SetActive()
	}

	req.Records = answers
	if len(req.Records) == 0 {
		// Check if this unresolved name should be output by the enumeration
		if ds.Config().IncludeUnresolvable && ds.Config().IsDomainInScope(req.Name) {
			ds.Bus().Publish(core.OutputTopic, &core.Output{
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

func (ds *DNSService) newSubdomain(req *core.Request, times int) {
	if req != nil && times == 1 {
		go ds.processSubdomain(req)
	}
}

func (ds *DNSService) processSubdomain(req *core.Request) {
	ds.SetActive()
	ds.basicQueries(req.Name, req.Domain)
	ds.queryServiceNames(req.Name, req.Domain)
}

func (ds *DNSService) basicQueries(subdomain, domain string) {
	var answers []core.DNSAnswer

	ds.SetActive()
	// Obtain the DNS answers for the NS records related to the domain
	ds.sendQueryTime(time.Now())
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
		ds.Config().Log.Printf("DNS: NS record query error: %s: %v", subdomain, err)
	}

	ds.SetActive()
	// Obtain the DNS answers for the MX records related to the domain
	ds.sendQueryTime(time.Now())
	if ans, err := Resolve(subdomain, "MX"); err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	} else {
		ds.Config().Log.Printf("DNS: MX record query error: %s: %v", subdomain, err)
	}

	ds.SetActive()
	// Obtain the DNS answers for the SOA records related to the domain
	ds.sendQueryTime(time.Now())
	if ans, err := Resolve(subdomain, "SOA"); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Config().Log.Printf("DNS: SOA record query error: %s: %v", subdomain, err)
	}

	ds.SetActive()
	// Obtain the DNS answers for the SPF records related to the domain
	ds.sendQueryTime(time.Now())
	if ans, err := Resolve(subdomain, "SPF"); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Config().Log.Printf("DNS: SPF record query error: %s: %v", subdomain, err)
	}

	if len(answers) > 0 {
		ds.SetActive()
		ds.resolvedName(&core.Request{
			Name:    subdomain,
			Domain:  domain,
			Records: answers,
			Tag:     core.DNS,
			Source:  "Forward DNS",
		})
	}
}

func (ds *DNSService) attemptZoneXFR(sub, domain, server string) {
	if ds.filter.Duplicate(sub + server) {
		return
	}

	if requests, err := ZoneTransfer(sub, domain, server); err == nil {
		for _, req := range requests {
			ds.resolvedName(req)
		}
	} else {
		ds.Config().Log.Printf("DNS: Zone XFR failed: %s: %v", sub, err)
	}
}

func (ds *DNSService) queryServiceNames(subdomain, domain string) {
	ds.SetActive()
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		if ds.filter.Duplicate(srvName) {
			continue
		}
		ds.sendQueryTime(time.Now())
		if a, err := Resolve(srvName, "SRV"); err == nil {
			ds.resolvedName(&core.Request{
				Name:    srvName,
				Domain:  domain,
				Records: a,
				Tag:     core.DNS,
				Source:  "Forward DNS",
			})
		}
	}
}

func (ds *DNSService) dnsSweep(addr string, cidr *net.IPNet) {
	ds.SetActive()
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
		ds.reverseDNSQuery(a)
	}
}

func (ds *DNSService) reverseDNSQuery(ip string) {
	ds.SetActive()
	ds.sendQueryTime(time.Now())
	ptr, answer, err := Reverse(ip)
	if err != nil {
		return
	}
	// Check that the name discovered is in scope
	domain := ds.Config().WhichDomain(answer)
	if domain == "" {
		return
	}
	ds.resolvedName(&core.Request{
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
func (ds *DNSService) MatchesWildcard(req *core.Request) bool {
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
func (ds *DNSService) GetWildcardType(req *core.Request) int {
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

func (ds *DNSService) performWildcardRequest(req *core.Request) int {
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
			} else if compareAnswers(req.Records, w.Answers) {
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
			if !compareAnswers(set[i], set[i+1]) {
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

func (ds *DNSService) wildcardTestResults(sub string) []core.DNSAnswer {
	var answers []core.DNSAnswer

	name := UnlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	ds.sendQueryTime(time.Now())
	if a, err := Resolve(name, "CNAME"); err == nil {
		answers = append(answers, a...)
	}
	ds.sendQueryTime(time.Now())
	if a, err := Resolve(name, "A"); err == nil {
		answers = append(answers, a...)
	}
	ds.sendQueryTime(time.Now())
	if a, err := Resolve(name, "AAAA"); err == nil {
		answers = append(answers, a...)
	}

	if len(answers) == 0 {
		return nil
	}
	return answers
}

func compareAnswers(ans1, ans2 []core.DNSAnswer) bool {
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
