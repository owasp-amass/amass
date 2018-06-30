// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strings"
	"time"

	evbus "github.com/asaskevich/EventBus"
	"github.com/caffix/amass/amass/internal/dns"
)

type DNSService struct {
	BaseAmassService

	bus evbus.Bus

	// Ensures we do not resolve names more than once
	inFilter map[string]struct{}

	// Data collected about various subdomains
	subdomains map[string]map[int][]string
}

func NewDNSService(config *AmassConfig, bus evbus.Bus) *DNSService {
	ds := &DNSService{
		bus:        bus,
		inFilter:   make(map[string]struct{}),
		subdomains: make(map[string]map[int][]string),
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
			go ds.performDNSRequest()
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

func (ds *DNSService) performDNSRequest() {
	var err error
	var answers []dns.DNSAnswer

	req := ds.NextRequest()
	// Plow through the requests that are not of interest
	for req != nil && (req.Name == "" || req.Domain == "" ||
		ds.duplicate(req.Name) || ds.Config().Blacklisted(req.Name)) {
		req = ds.NextRequest()
	}
	if req == nil {
		return
	}
	ds.SetActive()

	answers, err = dns.ObtainAllRecords(req.Name)
	if err != nil {
		ds.Config().Log.Printf("DNS resolution error: %s: %v", req.Name, err)
		return
	}
	req.Records = answers

	if req.Tag != SCRAPE && req.Tag != CERT &&
		dns.DetectWildcard(req.Domain, req.Name, req.Records) {
		return
	}
	// Make sure we know about any new subdomains
	ds.checkForNewSubdomain(req)
	// The subdomain manager is now done with it
	ds.bus.Publish(RESOLVED, req)
}

func (ds *DNSService) checkForNewSubdomain(req *AmassRequest) {
	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return
	}
	// Do not further evaluate service subdomains
	if labels[1] == "_tcp" || labels[1] == "_udp" {
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
	if dns.DetectWildcard(req.Domain, req.Name, req.Records) {
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
	var answers []dns.DNSAnswer

	// Obtain the DNS answers for the NS records related to the domain
	if ans, err := dns.Resolve(subdomain, "NS"); err == nil {
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
	if ans, err := dns.Resolve(subdomain, "MX"); err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	} else {
		ds.Config().Log.Printf("DNS MX record query error: %s: %v", subdomain, err)
	}
	// Obtain the DNS answers for the SOA records related to the domain
	if ans, err := dns.Resolve(subdomain, "SOA"); err == nil {
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
	if names, err := dns.ZoneTransfer(domain, sub, server); err == nil {
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
	var answers []dns.DNSAnswer

	// Check all the popular SRV records
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		if ans, err := dns.Resolve(srvName, "SRV"); err == nil {
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
