// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"errors"
	"strings"
	"sync"
	"time"

	"github.com/caffix/recon"
)

const (
	maxNameLen  = 253
	maxLabelLen = 63

	ldhChars = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

// The SRV records often utilized by organizations on the Internet
var popularSRVRecords = []string{
	"_caldav._tcp",
	"_caldavs._tcp",
	"_ceph._tcp",
	"_ceph-mon._tcp",
	"_www._tcp",
	"_http._tcp",
	"_www-http._tcp",
	"_http._sctp",
	"_smtp._tcp",
	"_smtp._udp",
	"_submission._tcp",
	"_submission._udp",
	"_submissions._tcp",
	"_pop2._tcp",
	"_pop2._udp",
	"_pop3._tcp",
	"_pop3._udp",
	"_hybrid-pop._tcp",
	"_hybrid-pop._udp",
	"_pop3s._tcp",
	"_pop3s._udp",
	"_imap._tcp",
	"_imap._udp",
	"_imap3._tcp",
	"_imap3._udp",
	"_imaps._tcp",
	"_imaps._udp",
	"_hip-nat-t._udp",
	"_kerberos._tcp",
	"_kerberos._udp",
	"_kerberos-master._tcp",
	"_kerberos-master._udp",
	"_kpasswd._tcp",
	"_kpasswd._udp",
	"_kerberos-adm._tcp",
	"_kerberos-adm._udp",
	"_kerneros-iv._udp",
	"_kftp-data._tcp",
	"_kftp-data._udp",
	"_kftp._tcp",
	"_kftp._udp",
	"_ktelnet._tcp",
	"_ktelnet._udp",
	"_afs3-kaserver._tcp",
	"_afs3-kaserver._udp",
	"_ldap._tcp",
	"_ldap._udp",
	"_ldaps._tcp",
	"_ldaps._udp",
	"_www-ldap-gw._tcp",
	"_www-ldap-gw._udp",
	"_msft-gc-ssl._tcp",
	"_msft-gc-ssl._udp",
	"_ldap-admin._tcp",
	"_ldap-admin._udp",
	"_avatars._tcp",
	"_avatars-sec._tcp",
	"_matrix-vnet._tcp",
	"_puppet._tcp",
	"_x-puppet._tcp",
	"_stun._tcp",
	"_stun._udp",
	"_stun-behavior._tcp",
	"_stun-behavior._udp",
	"_stuns._tcp",
	"_stuns._udp",
	"_stun-behaviors._tcp",
	"_stun-behaviors._udp",
	"_stun-p1._tcp",
	"_stun-p1._udp",
	"_stun-p2._tcp",
	"_stun-p2._udp",
	"_stun-p3._tcp",
	"_stun-p3._udp",
	"_stun-port._tcp",
	"_stun-port._udp",
	"_sip._tcp",
	"_sip._udp",
	"_sip._sctp",
	"_sips._tcp",
	"_sips._udp",
	"_sips._sctp",
	"_xmpp-client._tcp",
	"_xmpp-client._udp",
	"_xmpp-server._tcp",
	"_xmpp-server._udp",
	"_jabber._tcp",
	"_xmpp-bosh._tcp",
	"_presence._tcp",
	"_presence._udp",
	"_rwhois._tcp",
	"_rwhois._udp",
	"_whoispp._tcp",
	"_whoispp._udp",
	"_ts3._udp",
	"_tsdns._tcp",
	"_matrix._tcp",
	"_minecraft._tcp",
	"_imps-server._tcp",
	"_autodiscover._tcp",
	"_nicname._tcp",
	"_nicname._udp",
}

type DNSService struct {
	BaseAmassService

	// The request queued up for DNS resolution
	queue []*AmassRequest

	// Ensures we do not resolve names more than once
	inFilter map[string]struct{}

	// Ensures we do not send out names more than once
	outFilter map[string]struct{}

	// Provides a way to check if we're seeing a new root domain
	domains map[string]struct{}

	// Results from the initial domain queries come here
	internal chan *AmassRequest
}

func NewDNSService(in, out chan *AmassRequest, config *AmassConfig) *DNSService {
	ds := &DNSService{
		inFilter:  make(map[string]struct{}),
		outFilter: make(map[string]struct{}),
		domains:   make(map[string]struct{}),
		internal:  make(chan *AmassRequest, 50),
	}

	ds.BaseAmassService = *NewBaseAmassService("DNS Service", config, ds)

	ds.input = in
	ds.output = out
	return ds
}

func (ds *DNSService) OnStart() error {
	ds.BaseAmassService.OnStart()

	go ds.processRequests()
	return nil
}

func (ds *DNSService) OnStop() error {
	ds.BaseAmassService.OnStop()
	return nil
}

func (ds *DNSService) basicQueries(domain string) {
	var answers []recon.DNSAnswer

	// Obtain CNAME, A and AAAA records for the root domain name
	ans, err := DNS.Query(domain, Resolvers.NextNameserver())
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the NS records related to the domain
	ans, err = recon.ResolveDNS(domain, Resolvers.NextNameserver(), "NS")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the MX records related to the domain
	ans, err = recon.ResolveDNS(domain, Resolvers.NextNameserver(), "MX")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the TXT records related to the domain
	ans, err = recon.ResolveDNS(domain, Resolvers.NextNameserver(), "TXT")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the SOA records related to the domain
	ans, err = recon.ResolveDNS(domain, Resolvers.NextNameserver(), "SOA")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Check all the popular SRV records
	for _, name := range popularSRVRecords {
		srvName := name + "." + domain

		ans, err = recon.ResolveDNS(srvName, Resolvers.NextNameserver(), "SRV")
		if err == nil {
			answers = append(answers, ans...)
			for _, a := range ans {
				if srvName != a.Name {
					continue
				}
				ds.internal <- &AmassRequest{
					Name:   a.Name,
					Domain: domain,
					Tag:    "dns",
					Source: "Forward DNS",
				}
			}
		}
	}
	// Only return names within the domain name of interest
	re := SubdomainRegex(domain)
	for _, a := range answers {
		for _, sd := range re.FindAllString(a.Data, -1) {
			ds.internal <- &AmassRequest{
				Name:   sd,
				Domain: domain,
				Tag:    "dns",
				Source: "Forward DNS",
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
		case i := <-ds.internal:
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

func (ds *DNSService) duplicate(name string) bool {
	ds.Lock()
	defer ds.Unlock()

	if _, found := ds.inFilter[name]; found {
		return true
	}
	ds.inFilter[name] = struct{}{}
	return false
}

func (ds *DNSService) addToQueue(req *AmassRequest) {
	if _, found := ds.domains[req.Domain]; !found {
		ds.domains[req.Domain] = struct{}{}
		go ds.basicQueries(req.Domain)
	}
	if req.Name != "" && !ds.duplicate(req.Name) {
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

func (ds *DNSService) alreadySent(name string) bool {
	ds.Lock()
	defer ds.Unlock()

	if _, found := ds.outFilter[name]; found {
		return true
	}
	ds.outFilter[name] = struct{}{}
	return false
}

func (ds *DNSService) performDNSRequest(req *AmassRequest) {
	answers, err := DNS.Query(req.Name, Resolvers.NextNameserver())
	if err != nil {
		return
	}
	// Pull the IP address out of the DNS answers
	ipstr := recon.GetARecordData(answers)
	if ipstr == "" {
		return
	}
	req.Address = ipstr

	match := DetectDNSWildcard(req)
	// If the name didn't come from a search, check it doesn't match a wildcard IP address
	if req.Tag != SEARCH && match {
		return
	}
	// Return the successfully resolved names + address
	for _, record := range answers {
		name := removeLastDot(record.Name)

		// Should this name be sent out?
		if !strings.HasSuffix(name, req.Domain) || ds.alreadySent(name) {
			continue
		}
		// Check which tag and source info to attach
		tag := "dns"
		source := "Forward DNS"
		if name == req.Name {
			tag = req.Tag
			source = req.Source
		}
		ds.SendOut(&AmassRequest{
			Name:    name,
			Domain:  req.Domain,
			Address: ipstr,
			Tag:     tag,
			Source:  source,
		})
	}
}

//-------------------------------------------------------------------------------------------------
// DNS Query

type queries struct {
	sync.Mutex

	// Caches the results from previous DNS queries
	cache map[string][]recon.DNSAnswer
}

var DNS *queries

func init() {
	DNS = &queries{cache: make(map[string][]recon.DNSAnswer)}
}

func (q *queries) addToCache(name string, ans []recon.DNSAnswer) {
	q.Lock()
	defer q.Unlock()

	q.cache[name] = ans
}

func (q *queries) cacheLookup(name string) []recon.DNSAnswer {
	q.Lock()
	defer q.Unlock()

	if entry, found := q.cache[name]; found {
		return entry
	}
	return []recon.DNSAnswer{}
}

// Query - Performs the DNS resolution and pulls names out of the errors or answers
func (q *queries) Query(name, server string) ([]recon.DNSAnswer, error) {
	var resolved bool
	var answers []recon.DNSAnswer

	ans, n := serviceName(name, server)
	if n != "" {
		answers = append(answers, ans...)
		name = n
	}
	ans, n = q.recursiveCNAME(name, server)
	if len(ans) > 0 {
		answers = append(answers, ans...)
		name = n
	}
	// Obtain the DNS answers for the A records related to the name
	ans = q.Lookup(name, server, "A")
	if len(ans) > 0 {
		answers = append(answers, ans...)
		resolved = true
	}
	// Obtain the DNS answers for the AAAA records related to the name
	ans = q.Lookup(name, server, "AAAA")
	if len(ans) > 0 {
		answers = append(answers, ans...)
		resolved = true
	}

	if !resolved {
		return []recon.DNSAnswer{}, errors.New("No A or AAAA records resolved for the name")
	}
	return answers, nil
}

// serviceName - Obtain the DNS answers and target name for the  SRV record
func serviceName(name, server string) ([]recon.DNSAnswer, string) {
	ans, err := recon.ResolveDNS(name, server, "SRV")
	if err == nil {
		return ans, removeLastDot(ans[0].Data)
	}
	return nil, ""
}

func (q *queries) recursiveCNAME(name, server string) ([]recon.DNSAnswer, string) {
	var answers []recon.DNSAnswer

	// Recursively resolve the CNAME records
	for i := 0; i < 10; i++ {
		a := q.Lookup(name, server, "CNAME")
		if len(a) == 0 {
			break
		}
		// Update the answers and current name
		answers = append(answers, a[0])
		name = removeLastDot(a[0].Data)
	}
	return answers, name
}

func (q *queries) Lookup(name, server, t string) []recon.DNSAnswer {
	var err error

	// Check if we have this name already
	a := q.cacheLookup(name)
	if len(a) == 0 {
		// Otherwise, perform the DNS query and add to the cache
		a, err = recon.ResolveDNS(name, server, t)
		if err == nil {
			q.addToCache(name, a)
		}
	}
	return a
}

func removeLastDot(name string) string {
	sz := len(name)

	if sz > 0 && name[sz-1] == '.' {
		return name[:sz-1]
	}
	return name
}
