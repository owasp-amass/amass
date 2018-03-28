// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

const (
	maxNameLen  = 253
	maxLabelLen = 63

	ldhChars = "abcdefghijklmnopqrstuvwxyz0123456789-"
)

type DNSAnswer struct {
	Name string `json:"name"`
	Type int    `json:"type"`
	TTL  int    `json:"TTL"`
	Data string `json:"data"`
}

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
	subdomains map[string]struct{}

	// Results from the initial domain queries come here
	internal chan *AmassRequest
}

func NewDNSService(in, out chan *AmassRequest, config *AmassConfig) *DNSService {
	ds := &DNSService{
		queue:      make([]*AmassRequest, 0, 50),
		inFilter:   make(map[string]struct{}),
		outFilter:  make(map[string]struct{}),
		subdomains: make(map[string]struct{}),
		internal:   make(chan *AmassRequest, 50),
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

func (ds *DNSService) basicQueries(subdomain, domain string) {
	var answers []DNSAnswer

	dc := ds.Config().DNSDialContext
	// Obtain CNAME, A and AAAA records for the root domain name
	ans, err := ds.Config().dns.Query(subdomain)
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the NS records related to the domain
	ans, err = ResolveDNSWithDialContext(dc, subdomain, "NS")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the MX records related to the domain
	ans, err = ResolveDNSWithDialContext(dc, subdomain, "MX")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the TXT records related to the domain
	ans, err = ResolveDNSWithDialContext(dc, subdomain, "TXT")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the SOA records related to the domain
	ans, err = ResolveDNSWithDialContext(dc, subdomain, "SOA")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Check all the popular SRV records
	for _, name := range popularSRVRecords {
		srvName := name + "." + domain

		ans, err = ResolveDNSWithDialContext(dc, srvName, "SRV")
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
			ds.addToQueue(add)
		case i := <-ds.internal:
			// Mark the service as active
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
	if _, found := ds.inFilter[name]; found {
		return true
	}
	ds.inFilter[name] = struct{}{}
	return false
}

func (ds *DNSService) dupSubdomain(sub string) bool {
	ds.Lock()
	defer ds.Unlock()

	if _, found := ds.subdomains[sub]; found {
		return true
	}
	ds.subdomains[sub] = struct{}{}
	return false
}

func (ds *DNSService) addToQueue(req *AmassRequest) {
	if req.Name != "" && !ds.duplicate(req.Name) {
		ds.queue = append(ds.queue, req)
	}
}

func (ds *DNSService) checkForNewSubdomain(req *AmassRequest) {
	// If the Name is empty, we are done here
	if req.Name == "" {
		return
	}

	labels := strings.Split(req.Name, ".")
	num := len(labels)
	// Is this large enough to consider further?
	if num < 2 {
		return
	}
	// Have we already seen this subdomain?
	sub := strings.Join(labels[1:], ".")
	if ds.dupSubdomain(sub) {
		return
	}
	// It cannot have fewer labels than the root domain name
	if num < len(strings.Split(req.Domain, ".")) {
		return
	}
	// Does this subdomain have a wildcard?
	if ds.Config().wildcards.DetectWildcard(req) {
		return
	}
	// Otherwise, run the basic queries against this name
	go ds.basicQueries(sub, req.Domain)
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
	config := ds.Config()

	answers, err := config.dns.Query(req.Name)
	if err != nil {
		return
	}
	// Pull the IP address out of the DNS answers
	ipstr := GetARecordData(answers)
	if ipstr == "" {
		return
	}
	req.Address = ipstr

	match := ds.Config().wildcards.DetectWildcard(req)
	// If the name didn't come from a search, check it doesn't match a wildcard IP address
	if req.Tag != SEARCH && match {
		return
	}
	// Attempt to obtain subdomain specific information
	go ds.checkForNewSubdomain(req)
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

	// Configuration for the amass enumeration
	config *AmassConfig
}

func newQueriesSubsystem(config *AmassConfig) *queries {
	return &queries{config: config}
}

// Query - Performs the DNS resolution and pulls names out of the errors or answers
func (q *queries) Query(name string) ([]DNSAnswer, error) {
	var resolved bool
	var answers []DNSAnswer

	ans, n := q.serviceName(name)
	if n != "" {
		answers = append(answers, ans...)
		name = n
	}
	ans, n = q.recursiveCNAME(name)
	if len(ans) > 0 {
		answers = append(answers, ans...)
		name = n
	}
	// Obtain the DNS answers for the A records related to the name
	ans = q.Lookup(name, "A")
	if len(ans) > 0 {
		answers = append(answers, ans...)
		resolved = true
	}
	// Obtain the DNS answers for the AAAA records related to the name
	ans = q.Lookup(name, "AAAA")
	if len(ans) > 0 {
		answers = append(answers, ans...)
		resolved = true
	}

	if !resolved {
		return []DNSAnswer{}, errors.New("No A or AAAA records resolved for the name")
	}
	return answers, nil
}

// serviceName - Obtain the DNS answers and target name for the  SRV record
func (q *queries) serviceName(name string) ([]DNSAnswer, string) {
	ans, err := ResolveDNSWithDialContext(q.config.DNSDialContext, name, "SRV")
	if err == nil {
		return ans, removeLastDot(ans[0].Data)
	}
	return nil, ""
}

func (q *queries) recursiveCNAME(name string) ([]DNSAnswer, string) {
	var answers []DNSAnswer

	// Recursively resolve the CNAME records
	for i := 0; i < 10; i++ {
		a := q.Lookup(name, "CNAME")
		if len(a) == 0 {
			break
		}
		// Update the answers and current name
		answers = append(answers, a[0])
		name = removeLastDot(a[0].Data)
	}
	return answers, name
}

func (q *queries) Lookup(name, t string) []DNSAnswer {
	// Perform the DNS query
	a, err := ResolveDNSWithDialContext(q.config.DNSDialContext, name, t)
	if err == nil {
		return a
	}
	return []DNSAnswer{}
}

//-------------------------------------------------------------------------------------------------
// All usage of the miekg/dns package

func ResolveDNSWithDialContext(dc dialCtx, name, qtype string) ([]DNSAnswer, error) {
	var qt uint16

	switch qtype {
	case "CNAME":
		qt = dns.TypeCNAME
	case "A":
		qt = dns.TypeA
	case "AAAA":
		qt = dns.TypeAAAA
	case "PTR":
		qt = dns.TypePTR
	case "NS":
		qt = dns.TypeNS
	case "MX":
		qt = dns.TypeMX
	case "TXT":
		qt = dns.TypeTXT
	case "SOA":
		qt = dns.TypeSOA
	case "SPF":
		qt = dns.TypeSPF
	case "SRV":
		qt = dns.TypeSRV
	default:
		return []DNSAnswer{}, errors.New("Unsupported DNS type")
	}

	conn, err := dc(context.Background(), "udp", "")
	if err != nil {
		return []DNSAnswer{}, errors.New("Failed to connect to the server")
	}

	ans := DNSExchange(conn, name, qt)
	if len(ans) == 0 {
		return []DNSAnswer{}, errors.New("The query was unsuccessful")
	}
	return ans, nil
}

// DNSExchange - Encapsulates miekg/dns usage
func DNSExchange(conn net.Conn, name string, qtype uint16) []DNSAnswer {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
			Id:                dns.Id(),
			Rcode:             dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: uint16(dns.ClassINET),
	}
	m.Extra = append(m.Extra, setupOptions())

	var answers []DNSAnswer
	// Perform the DNS query
	co := &dns.Conn{Conn: conn}
	defer conn.Close()
	co.WriteMsg(m)
	r, err := co.ReadMsg()
	if err != nil {
		return answers
	}
	// Check that the query was successful
	if r != nil && r.Rcode != dns.RcodeSuccess {
		return answers
	}

	var data []string
	for _, a := range r.Answer {
		if a.Header().Rrtype == qtype {
			switch qtype {
			case dns.TypeA:
				if t, ok := a.(*dns.A); ok {
					data = append(data, t.A.String())
				}
			case dns.TypeAAAA:
				if t, ok := a.(*dns.AAAA); ok {
					data = append(data, t.AAAA.String())
				}
			case dns.TypeCNAME:
				if t, ok := a.(*dns.CNAME); ok {
					data = append(data, t.Target)
				}
			case dns.TypePTR:
				if t, ok := a.(*dns.PTR); ok {
					data = append(data, t.Ptr)
				}
			case dns.TypeNS:
				if t, ok := a.(*dns.NS); ok {
					data = append(data, t.Ns)
				}
			case dns.TypeMX:
				if t, ok := a.(*dns.MX); ok {
					data = append(data, t.Mx)
				}
			case dns.TypeTXT:
				if t, ok := a.(*dns.TXT); ok {
					var all string

					for _, piece := range t.Txt {
						all += piece + " "
					}
					data = append(data, all)
				}
			case dns.TypeSOA:
				if t, ok := a.(*dns.SOA); ok {
					data = append(data, t.Ns+" "+t.Mbox)
				}
			case dns.TypeSPF:
				if t, ok := a.(*dns.SPF); ok {
					var all string

					for _, piece := range t.Txt {
						all += piece + " "
					}
					data = append(data, all)
				}
			case dns.TypeSRV:
				if t, ok := a.(*dns.SRV); ok {
					data = append(data, t.Target)
				}
			}
		}
	}

	for _, a := range data {
		answers = append(answers, DNSAnswer{
			Name: name,
			Type: int(qtype),
			TTL:  0,
			Data: strings.TrimSpace(a),
		})
	}
	return answers
}

// setupOptions - Returns the EDNS0_SUBNET option for hiding our location
func setupOptions() *dns.OPT {
	e := &dns.EDNS0_SUBNET{
		Code:          dns.EDNS0SUBNET,
		Family:        1,
		SourceNetmask: 0,
		SourceScope:   0,
		Address:       net.ParseIP("0.0.0.0").To4(),
	}

	return &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
		Option: []dns.EDNS0{e},
	}
}

func ReverseDNSWithDialContext(dc dialCtx, ip string) (string, error) {
	var name string

	addr := reverseIP(ip) + ".in-addr.arpa"
	answers, err := ResolveDNSWithDialContext(dc, addr, "PTR")
	if err == nil {
		if answers[0].Type == 12 {
			l := len(answers[0].Data)

			name = answers[0].Data[:l-1]
		}

		if name == "" {
			err = errors.New("PTR record not found")
		}
	}
	return name, err
}

// Goes through the DNS answers looking for A and AAAA records,
// and returns the first Data field found for those types
func GetARecordData(answers []DNSAnswer) string {
	var data string

	for _, a := range answers {
		if a.Type == 1 || a.Type == 28 {
			data = a.Data
			break
		}
	}
	return data
}

func reverseIP(ip string) string {
	var reversed []string

	parts := strings.Split(ip, ".")
	li := len(parts) - 1

	for i := li; i >= 0; i-- {
		reversed = append(reversed, parts[i])
	}

	return strings.Join(reversed, ".")
}

func removeLastDot(name string) string {
	sz := len(name)

	if sz > 0 && name[sz-1] == '.' {
		return name[:sz-1]
	}
	return name
}
