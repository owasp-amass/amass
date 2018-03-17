// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"math/rand"
	"strings"
	"sync"
	"time"

	"github.com/caffix/amass/amass/stringset"
	"github.com/caffix/recon"
)

const (
	maxNameLen  = 253
	maxLabelLen = 63

	ldhChars = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// Public & free DNS servers
var knownPublicServers = []string{
	"8.8.8.8:53",         // Google
	"64.6.64.6:53",       // Verisign
	"9.9.9.9:53",         // Quad9
	"84.200.69.80:53",    // DNS.WATCH
	"8.26.56.26:53",      // Comodo Secure DNS
	"208.67.222.222:53",  // OpenDNS Home
	"195.46.39.39:53",    // SafeDNS
	"69.195.152.204:53",  // OpenNIC
	"216.146.35.35:53",   // Dyn
	"198.101.242.72:53",  // Alternate DNS
	"77.88.8.8:53",       // Yandex.DNS
	"91.239.100.100:53",  // UncensoredDNS
	"74.82.42.42:53",     // Hurricane Electric
	"156.154.70.1:53",    // Neustar
	"8.8.4.4:53",         // Google Secondary
	"149.112.112.112:53", // Quad9 Secondary
	"84.200.70.40:53",    // DNS.WATCH Secondary
	"8.20.247.20:53",     // Comodo Secure DNS Secondary
	"208.67.220.220:53",  // OpenDNS Home Secondary
	"195.46.39.40:53",    // SafeDNS Secondary
	"216.146.36.36:53",   // Dyn Secondary
	"77.88.8.1:53",       // Yandex.DNS Secondary
	"89.233.43.71:53",    // UncensoredDNS Secondary
	"156.154.71.1:53",    // Neustar Secondary
	"37.235.1.174:53",    // FreeDNS
	"37.235.1.177:53",    // FreeDNS Secondary
	"23.253.163.53:53",   // Alternate DNS Secondary
	"64.6.65.6:53",       // Verisign Secondary
}

var Servers *PublicDNSMonitor

type serverStats struct {
	Responding  bool
	NumRequests int
}

func init() {
	Servers = NewPublicDNSMonitor()
}

// Checks in real-time if the public DNS servers have become unusable
type PublicDNSMonitor struct {
	sync.Mutex

	// List of servers that we know about
	knownServers []string

	// Tracking for which servers continue to be usable
	usableServers map[string]*serverStats

	// Requests for a server from the queue come here
	nextServer chan chan string
}

func NewPublicDNSMonitor() *PublicDNSMonitor {
	pdm := &PublicDNSMonitor{
		knownServers:  knownPublicServers,
		usableServers: make(map[string]*serverStats),
		nextServer:    make(chan chan string, 100),
	}
	pdm.testAllServers()
	go pdm.processServerQueue()
	return pdm
}

func (pdm *PublicDNSMonitor) testAllServers() {
	for _, server := range pdm.knownServers {
		pdm.testServer(server)
	}
}

func (pdm *PublicDNSMonitor) testServer(server string) bool {
	var resp bool

	_, err := recon.ResolveDNS(pickRandomTestName(), server, "A")
	if err == nil {
		resp = true
	}

	if _, found := pdm.usableServers[server]; !found {
		pdm.usableServers[server] = new(serverStats)
	}

	pdm.usableServers[server].NumRequests = 0
	pdm.usableServers[server].Responding = resp
	return resp
}

func pickRandomTestName() string {
	num := rand.Int()
	names := []string{"google.com", "twitter.com", "linkedin.com",
		"facebook.com", "amazon.com", "github.com", "apple.com"}

	sel := num % len(names)
	return names[sel]
}

func (pdm *PublicDNSMonitor) processServerQueue() {
	var queue []string

	for {
		select {
		case resp := <-pdm.nextServer:
			if len(queue) == 0 {
				queue = pdm.getServerList()
			}
			resp <- queue[0]

			if len(queue) == 1 {
				queue = []string{}
			} else if len(queue) > 1 {
				queue = queue[1:]
			}
		}
	}
}

func (pdm *PublicDNSMonitor) getServerList() []string {
	pdm.Lock()
	defer pdm.Unlock()

	// Check for servers that need to be tested
	for svr, stats := range pdm.usableServers {
		if !stats.Responding {
			continue
		}

		stats.NumRequests++
		if stats.NumRequests%50 == 0 {
			pdm.testServer(svr)
		}
	}

	var servers []string
	// Build the slice of responding servers
	for svr, stats := range pdm.usableServers {
		if stats.Responding {
			servers = append(servers, svr)
		}
	}
	return servers
}

// NextNameserver - Requests the next server
func (pdm *PublicDNSMonitor) NextNameserver() string {
	ans := make(chan string, 2)

	pdm.nextServer <- ans
	return <-ans
}

//-------------------------------------------------------------------------------------------
// DNSService implementation

type wildcard struct {
	Req *AmassRequest
	Ans chan bool
}

type DNSService struct {
	BaseAmassService

	// The request queued up for DNS resolution
	queue []*AmassRequest

	// Ensures we do not resolve names more than once
	filter map[string]struct{}

	// Requests are sent through this channel to check DNS wildcard matches
	wildcards chan *wildcard

	// Results from the initial domain queries come here
	initial chan *AmassRequest
}

func NewDNSService(in, out chan *AmassRequest, config *AmassConfig) *DNSService {
	ds := &DNSService{
		filter:    make(map[string]struct{}),
		wildcards: make(chan *wildcard, 50),
		initial:   make(chan *AmassRequest, 50),
	}

	ds.BaseAmassService = *NewBaseAmassService("DNS Service", config, ds)

	ds.input = in
	ds.output = out
	return ds
}

func (ds *DNSService) OnStart() error {
	ds.BaseAmassService.OnStart()

	go ds.processWildcardMatches()
	go ds.processRequests()
	go ds.executeInitialQueries()
	return nil
}

func (ds *DNSService) OnStop() error {
	ds.BaseAmassService.OnStop()
	return nil
}

func (ds *DNSService) executeInitialQueries() {
	// Loop over all the domains provided by the config
	for _, domain := range ds.Config().Domains {
		var answers []recon.DNSAnswer

		// Obtain the DNS answers for the NS records related to the domain
		ans, err := recon.ResolveDNS(domain, Servers.NextNameserver(), "NS")
		if err == nil {
			answers = append(answers, ans...)
		}
		// Obtain the DNS answers for the MX records related to the domain
		ans, err = recon.ResolveDNS(domain, Servers.NextNameserver(), "MX")
		if err == nil {
			answers = append(answers, ans...)
		}
		// Only return names within the domain name of interest
		re := SubdomainRegex(domain)
		for _, a := range answers {
			for _, sd := range re.FindAllString(a.Data, -1) {
				ds.initial <- &AmassRequest{
					Name:   sd,
					Domain: domain,
					Tag:    DNS,
					Source: "Forward DNS",
				}
			}
		}
	}
}

func (ds *DNSService) processRequests() {
	t := time.NewTicker(ds.Config().Frequency)
	defer t.Stop()

	check := time.NewTicker(5 * time.Second)
	defer check.Stop()
loop:
	for {
		select {
		case add := <-ds.Input():
			// Mark the service as active
			ds.SetActive(true)
			ds.addToQueue(add)
		case i := <-ds.initial:
			// Mark the service as active
			ds.SetActive(true)
			ds.addToQueue(i)
		case <-t.C: // Pops a DNS name off the queue for resolution
			next := ds.nextFromQueue()

			if next != nil && next.Domain != "" {
				ds.SetActive(true)

				next.Name = trim252F(next.Name)
				go ds.performDNSRequest(next)
			}
		case <-check.C:
			if len(ds.queue) == 0 {
				// Mark the service as not active
				ds.SetActive(false)
			}
		case <-ds.Quit():
			break loop
		}
	}
}

func (ds *DNSService) addToQueue(req *AmassRequest) {
	if _, found := ds.filter[req.Name]; req.Name != "" && !found {
		ds.filter[req.Name] = struct{}{}
		ds.queue = append(ds.queue, req)
	}
}

func (ds *DNSService) nextFromQueue() *AmassRequest {
	var next *AmassRequest

	if len(ds.queue) > 0 {
		next = ds.queue[0]
		// Remove the first slice element
		if len(ds.queue) > 1 {
			ds.queue = ds.queue[1:]
		} else {
			ds.queue = []*AmassRequest{}
		}
	}
	return next
}

func (ds *DNSService) performDNSRequest(req *AmassRequest) {
	answers, err := dnsQuery(req.Domain, req.Name, Servers.NextNameserver())
	if err != nil {
		return
	}
	// Pull the IP address out of the DNS answers
	ipstr := recon.GetARecordData(answers)
	if ipstr == "" {
		return
	}
	req.Address = ipstr

	match := ds.dnsWildcardMatch(req)
	// If the name didn't come from a search, check it doesn't match a wildcard IP address
	if req.Tag != SEARCH && match {
		return
	}
	// Return the successfully resolved names + address
	for _, record := range answers {
		if !strings.HasSuffix(record.Name, req.Domain) {
			continue
		}

		tag := DNS
		source := "Forward DNS"
		if record.Name == req.Name {
			tag = req.Tag
			source = req.Source
		}
		ds.SendOut(&AmassRequest{
			Name:    trim252F(record.Name),
			Domain:  req.Domain,
			Address: ipstr,
			Tag:     tag,
			Source:  source,
		})
	}
}

// dnsQuery - Performs the DNS resolution and pulls names out of the errors or answers
func dnsQuery(domain, name, server string) ([]recon.DNSAnswer, error) {
	var resolved bool

	answers, name := recursiveCNAME(name, server)
	// Obtain the DNS answers for the A records related to the name
	ans, err := recon.ResolveDNS(name, server, "A")
	if err == nil {
		answers = append(answers, ans...)
		resolved = true
	}
	// Obtain the DNS answers for the AAAA records related to the name
	ans, err = recon.ResolveDNS(name, server, "AAAA")
	if err == nil {
		answers = append(answers, ans...)
		resolved = true
	}

	if !resolved {
		return []recon.DNSAnswer{}, errors.New("No A or AAAA records resolved for the name")
	}
	return answers, nil
}

func recursiveCNAME(name, server string) ([]recon.DNSAnswer, string) {
	var answers []recon.DNSAnswer

	// Recursively resolve the CNAME records
	for i := 0; i < 10; i++ {
		a, err := recon.ResolveDNS(name, server, "CNAME")
		if err != nil {
			break
		}

		answers = append(answers, a[0])
		name = a[0].Data
	}
	return answers, name
}

//--------------------------------------------------------------------------------------------
// Wildcard detection

type dnsWildcard struct {
	HasWildcard bool
	Answers     *stringset.StringSet
}

// DNSWildcardMatch - Checks subdomains in the wildcard cache for matches on the IP address
func (ds *DNSService) dnsWildcardMatch(req *AmassRequest) bool {
	answer := make(chan bool, 2)

	ds.wildcards <- &wildcard{
		Req: req,
		Ans: answer,
	}
	return <-answer
}

// Goroutine that keeps track of DNS wildcards discovered
func (ds *DNSService) processWildcardMatches() {
	wildcards := make(map[string]*dnsWildcard)
loop:
	for {
		select {
		case req := <-ds.wildcards:
			r := req.Req
			req.Ans <- matchesWildcard(r.Name, r.Domain, r.Address, wildcards)
		case <-ds.Quit():
			break loop
		}
	}
}

func matchesWildcard(name, root, ip string, wildcards map[string]*dnsWildcard) bool {
	var answer bool

	base := len(strings.Split(root, "."))
	// Obtain all parts of the subdomain name
	labels := strings.Split(name, ".")

	for i := len(labels) - base; i > 0; i-- {
		sub := strings.Join(labels[i:], ".")

		// See if detection has been performed for this subdomain
		w, found := wildcards[sub]
		if !found {
			entry := &dnsWildcard{
				HasWildcard: false,
				Answers:     nil,
			}
			// Try three times for good luck
			for i := 0; i < 3; i++ {
				// Does this subdomain have a wildcard?
				if ss := wildcardDetection(sub, root); ss != nil {
					entry.HasWildcard = true
					entry.Answers = ss
					break
				}
			}
			w = entry
			wildcards[sub] = w
		}
		// Check if the subdomain and address in question match a wildcard
		if w.HasWildcard && w.Answers.Contains(ip) {
			answer = true
		}
	}
	return answer
}

// wildcardDetection detects if a domain returns an IP
// address for "bad" names, and if so, which address(es) are used
func wildcardDetection(sub, root string) *stringset.StringSet {
	// An unlikely name will be checked for this subdomain
	name := unlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	ans, err := dnsQuery(root, name, Servers.NextNameserver())
	if err != nil {
		return nil
	}
	result := answersToStringSet(ans)
	if result.Empty() {
		return nil
	}
	return result
}

func unlikelyName(sub string) string {
	var newlabel string
	ldh := []byte(ldhChars)
	ldhLen := len(ldh)

	// Determine the max label length
	l := maxNameLen - len(sub)
	if l > maxLabelLen {
		l = maxLabelLen / 2
	} else if l < 1 {
		return ""
	}
	// Shuffle our LDH characters
	rand.Shuffle(ldhLen, func(i, j int) {
		ldh[i], ldh[j] = ldh[j], ldh[i]
	})

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

func answersToStringSet(answers []recon.DNSAnswer) *stringset.StringSet {
	ss := stringset.NewStringSet()

	for _, a := range answers {
		ss.Add(a.Data)
	}
	return ss
}
