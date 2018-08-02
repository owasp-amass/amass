// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"fmt"
	"strings"
	"time"

	udns "github.com/OWASP/Amass/amass/utils/dns"
	evbus "github.com/asaskevich/EventBus"
	"github.com/miekg/dns"
	"golang.org/x/sync/semaphore"
)

type DNSService struct {
	BaseAmassService

	bus evbus.Bus

	// Ensures we do not resolve names more than once
	filter map[string]struct{}

	// Data collected about various subdomains
	subdomains map[string]map[int][]string

	// Enforces a maximum number of DNS queries sent at any given moment
	sem *semaphore.Weighted
}

func NewDNSService(config *AmassConfig, bus evbus.Bus) *DNSService {
	// Obtain the proper weight based on file resource limits
	weight := (int64(GetFileLimit()) / 10) * 9
	if weight <= 0 {
		weight = 10000
	}

	ds := &DNSService{
		bus:        bus,
		filter:     make(map[string]struct{}),
		subdomains: make(map[string]map[int][]string),
		sem:        semaphore.NewWeighted(weight),
	}

	ds.BaseAmassService = *NewBaseAmassService("DNS Service", config, ds)
	return ds
}

func (ds *DNSService) OnStart() error {
	ds.BaseAmassService.OnStart()

	ds.bus.SubscribeAsync(DNSQUERY, ds.SendRequest, false)
	go ds.processRequests()
	return nil
}

func (ds *DNSService) OnStop() error {
	ds.BaseAmassService.OnStop()

	ds.bus.Unsubscribe(DNSQUERY, ds.SendRequest)
	return nil
}

func (ds *DNSService) processRequests() {
	t := time.NewTicker(ds.Config().Frequency)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			ds.performRequest()
		case <-ds.Quit():
			break loop
		}
	}
}

func (ds *DNSService) duplicate(name string) bool {
	ds.Lock()
	defer ds.Unlock()

	if _, found := ds.filter[name]; found {
		return true
	}
	ds.filter[name] = struct{}{}
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

var InitialQueryTypes = []uint16{
	dns.TypeTXT,
	dns.TypeA,
	dns.TypeAAAA,
	dns.TypeCNAME,
	dns.TypePTR,
	dns.TypeSRV,
}

func (ds *DNSService) completeQueries(req *AmassRequest) {
	defer ds.sem.Release(6)

	var answers []udns.DNSAnswer

	for _, t := range InitialQueryTypes {
		tries := 3
		if t == dns.TypeTXT {
			tries = 10
		}

		for i := 0; i < tries; i++ {
			a, err, again := ds.executeQuery(req.Name, t)
			if err == nil {
				answers = append(answers, a...)
				break
			}
			ds.Config().Log.Print(err)
			if !again {
				break
			}
		}
	}

	req.Records = answers
	if len(req.Records) == 0 {
		return
	}

	if req.Tag != SCRAPE && req.Tag != CERT &&
		udns.DetectWildcard(req.Domain, req.Name, req.Records) {
		return
	}
	// Make sure we know about any new subdomains
	ds.checkForNewSubdomain(req)
	ds.bus.Publish(RESOLVED, req)
}

func (ds *DNSService) executeQuery(name string, qtype uint16) ([]udns.DNSAnswer, error, bool) {
	var answers []udns.DNSAnswer

	conn, err := udns.DNSDialContext(context.Background(), "udp", "")
	if err != nil {
		return nil, fmt.Errorf("DNS error: Failed to create UDP connection to resolver: %v", err), false
	}
	defer conn.Close()

	co := &dns.Conn{Conn: conn}
	msg := udns.QueryMessage(name, qtype)

	co.SetWriteDeadline(time.Now().Add(1 * time.Second))
	if err = co.WriteMsg(msg); err != nil {
		return nil, fmt.Errorf("DNS error: Failed to write query msg: %v", err), false
	}

	co.SetReadDeadline(time.Now().Add(1 * time.Second))
	r, err := co.ReadMsg()
	if err != nil {
		return nil, fmt.Errorf("DNS error: Failed to read query response: %v", err), true
	}
	// Check that the query was successful
	if r != nil && r.Rcode != dns.RcodeSuccess {
		return nil, fmt.Errorf("DNS error: Resolver returned an error %v", r), false
	}

	for _, a := range udns.ExtractRawData(r, qtype) {
		answers = append(answers, udns.DNSAnswer{
			Name: name,
			Type: int(qtype),
			TTL:  0,
			Data: strings.TrimSpace(a),
		})
	}
	return answers, nil, false
}

func (ds *DNSService) checkForNewSubdomain(req *AmassRequest) {
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
	if udns.DetectWildcard(req.Domain, req.Name, req.Records) {
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
	var answers []udns.DNSAnswer

	// Obtain the DNS answers for the NS records related to the domain
	if ans, err := udns.Resolve(subdomain, "NS"); err == nil {
		for _, a := range ans {
			if ds.Config().Active {
				go ds.attemptZoneXFR(domain, subdomain, a.Data)
			}
			answers = append(answers, a)
		}
	} else {
		ds.Config().Log.Printf("DNS NS record query error: %s: %v", subdomain, err)
	}
	// Obtain the DNS answers for the MX records related to the domain
	if ans, err := udns.Resolve(subdomain, "MX"); err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	} else {
		ds.Config().Log.Printf("DNS MX record query error: %s: %v", subdomain, err)
	}
	// Obtain the DNS answers for the SOA records related to the domain
	if ans, err := udns.Resolve(subdomain, "SOA"); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.Config().Log.Printf("DNS SOA record query error: %s: %v", subdomain, err)
	}

	ds.bus.Publish(RESOLVED, &AmassRequest{
		Name:    subdomain,
		Domain:  domain,
		Records: answers,
		Tag:     "dns",
		Source:  "Forward DNS",
	})
}

func (ds *DNSService) attemptZoneXFR(domain, sub, server string) {
	if names, err := udns.ZoneTransfer(domain, sub, server); err == nil {
		for _, name := range names {
			ds.SendRequest(&AmassRequest{
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
	var answers []udns.DNSAnswer

	// Check all the popular SRV records
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		if ans, err := udns.Resolve(srvName, "SRV"); err == nil {
			answers = append(answers, ans...)
		} else {
			ds.Config().Log.Printf("DNS SRV record query error: %s: %v", srvName, err)
		}
		// Do not go too fast
		time.Sleep(ds.Config().Frequency)
	}

	ds.bus.Publish(RESOLVED, &AmassRequest{
		Name:    subdomain,
		Domain:  domain,
		Records: answers,
		Tag:     "dns",
		Source:  "Forward DNS",
	})
}

//-------------------------------------------------------------------------------------------------
// The SRV records often utilized by organizations on the Internet
//-------------------------------------------------------------------------------------------------

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
	"_collab-edge._tls",
}
