// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"errors"
	"net"
	"regexp"
	"strings"
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

	// Data collected about various subdomains
	subdomains map[string]map[int][]string

	// The channel that accepts new AmassRequests for the subdomain manager
	subMgrIn chan *AmassRequest
}

func NewDNSService(in, out chan *AmassRequest, config *AmassConfig) *DNSService {
	ds := &DNSService{
		queue:      make([]*AmassRequest, 0, 50),
		inFilter:   make(map[string]struct{}),
		outFilter:  make(map[string]struct{}),
		subdomains: make(map[string]map[int][]string),
		subMgrIn:   make(chan *AmassRequest, 50),
	}

	ds.BaseAmassService = *NewBaseAmassService("DNS Service", config, ds)

	ds.input = in
	ds.output = out
	return ds
}

func (ds *DNSService) OnStart() error {
	ds.BaseAmassService.OnStart()

	go ds.subdomainManager()
	go ds.processRequests()
	return nil
}

func (ds *DNSService) OnStop() error {
	ds.BaseAmassService.OnStop()
	return nil
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
			go ds.addToQueue(add)
		case <-t.C:
			go ds.performDNSRequest()
		case <-check.C:
			if len(ds.queue) == 0 {
				// Mark the service as NOT active
				ds.SetActive(false)
			}
		case <-ds.Quit():
			break loop
		}
	}
}

func (ds *DNSService) addToQueue(req *AmassRequest) {
	ds.Lock()
	defer ds.Unlock()

	ds.queue = append(ds.queue, req)
}

func (ds *DNSService) nextFromQueue() *AmassRequest {
	ds.Lock()
	defer ds.Unlock()

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

func (ds *DNSService) duplicate(name string) bool {
	ds.Lock()
	defer ds.Unlock()

	if _, found := ds.inFilter[name]; found {
		return true
	}
	ds.inFilter[name] = struct{}{}
	return false
}

func attemptsByTag(tag string) int {
	num := 1

	switch tag {
	case "dns", SCRAPE, ARCHIVE:
		num = 3
	}
	return num
}

func (ds *DNSService) performDNSRequest() {
	var err error
	var answers []DNSAnswer

	// Pops a DNS name off the queue for resolution
	req := ds.nextFromQueue()
	// Some initial input validation
	if req == nil || req.Name == "" || ds.duplicate(req.Name) || req.Domain == "" {
		return
	}

	ds.SetActive(true)
	dns := ds.Config().dns
	// Make multiple attempts based on source of the name
	num := attemptsByTag(req.Tag)
	for i := 0; i < num; i++ {
		// Query a DNS server for the new name
		answers, err = dns.Query(req.Name)
		if err == nil {
			break
		}
		time.Sleep(ds.Config().Frequency)
	}
	// If the name did not resolve, we are finished
	if err != nil {
		return
	}
	// Pull the IP address out of the DNS answers
	ipstr := GetARecordData(answers)
	if ipstr == "" {
		return
	}
	req.Address = ipstr

	wild := ds.Config().wildcards
	// If the name didn't come from a search, check for a wildcard IP address
	if req.Tag != SCRAPE && wild.DetectWildcard(req) {
		return
	}
	// Return the successfully resolved names + address
	for _, record := range answers {
		name := removeLastDot(record.Name)

		// Should this name be sent out?
		if !strings.HasSuffix(name, req.Domain) {
			continue
		}
		// Check which tag and source info to attach
		tag := "dns"
		source := "Forward DNS"
		if name == req.Name {
			tag = req.Tag
			source = req.Source
		}
		// Send the name to the subdomain manager
		ds.subMgrIn <- &AmassRequest{
			Name:    name,
			Domain:  req.Domain,
			Address: ipstr,
			Tag:     tag,
			Source:  source,
		}
	}
}

// subdomainManager - Goroutine that handles the discovery of new subdomains
// It is the last link in the chain before leaving the DNSService
func (ds *DNSService) subdomainManager() {
loop:
	for {
		select {
		case req := <-ds.subMgrIn:
			ds.performSubManagement(req)
		case <-ds.Quit():
			break loop
		}
	}
}

func (ds *DNSService) performSubManagement(req *AmassRequest) {
	ds.SetActive(true)
	// Do not process names we have already seen
	if ds.alreadySent(req.Name) {
		return
	}
	// Make sure we know about any new subdomains
	ds.checkForNewSubdomain(req)
	// Assign the correct type for Maltego
	req.Type = ds.getTypeOfHost(req.Name)
	// The subdomain manager is now done with it
	ds.SendOut(req)
}

func (ds *DNSService) alreadySent(name string) bool {
	if _, found := ds.outFilter[name]; found {
		return true
	}
	ds.outFilter[name] = struct{}{}
	return false
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
	if num < len(strings.Split(req.Domain, ".")) {
		return
	}
	// Does this subdomain have a wildcard?
	if ds.Config().wildcards.DetectWildcard(req) {
		return
	}
	// Otherwise, run the basic queries against this name
	ds.basicQueries(sub, req.Domain)
	go ds.queryServiceNames(sub, req.Domain)
}

func (ds *DNSService) dupSubdomain(sub string) bool {
	if _, found := ds.subdomains[sub]; found {
		return true
	}
	ds.subdomains[sub] = make(map[int][]string)
	return false
}

func (ds *DNSService) addSubdomainEntry(name string, qt int) {
	labels := strings.Split(name, ".")
	sub := strings.Join(labels[1:], ".")

	if _, found := ds.subdomains[sub]; !found {
		ds.subdomains[sub] = make(map[int][]string)
	}
	ds.subdomains[sub][qt] = UniqueAppend(ds.subdomains[sub][qt], name)
}

func (ds *DNSService) getTypeOfHost(name string) int {
	var qt int

	labels := strings.Split(name, ".")
	sub := strings.Join(labels[1:], ".")
loop:
	for t := range ds.subdomains[sub] {
		for _, n := range ds.subdomains[sub][t] {
			if n == name {
				qt = t
				break loop
			}
		}
	}
	// If no interesting type has been identified, check for web
	if qt == TypeNorm {
		re := regexp.MustCompile("web|www")

		if re.FindString(labels[0]) != "" {
			return TypeWeb
		}
	}
	return qt
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
	// Only return names within the domain name of interest
	re := SubdomainRegex(domain)
	for _, a := range answers {
		for _, sd := range re.FindAllString(a.Data, -1) {
			var rt int

			switch uint16(a.Type) {
			case dns.TypeNS:
				rt = TypeNS
				ds.addSubdomainEntry(sd, rt)
			case dns.TypeMX:
				rt = TypeMX
				ds.addSubdomainEntry(sd, rt)
			}
			// Put this on the DNSService.queue
			ds.addToQueue(&AmassRequest{
				Name:   sd,
				Type:   rt,
				Domain: domain,
				Tag:    "dns",
				Source: "Forward DNS",
			})
		}
	}
}

func (ds *DNSService) queryServiceNames(subdomain, domain string) {
	var answers []DNSAnswer

	dc := ds.Config().DNSDialContext
	// Check all the popular SRV records
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		ans, err := ResolveDNSWithDialContext(dc, srvName, "SRV")
		if err == nil {
			answers = append(answers, ans...)
			// Send the name of the service record itself as an AmassRequest
			for _, a := range ans {
				if srvName != a.Name {
					continue
				}
				// Put this on the DNSService.queue
				ds.addToQueue(&AmassRequest{
					Name:   a.Name,
					Domain: domain,
					Tag:    "dns",
					Source: "Forward DNS",
				})
			}
		}
		// Do not go too fast
		time.Sleep(ds.Config().Frequency)
	}
}

//-------------------------------------------------------------------------------------------------
// DNS Query

type queries struct {
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
	qt, err := textToTypeNum(qtype)
	if err != nil {
		return []DNSAnswer{}, err
	}
	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	conn, err := dc(ctx, "udp", "")
	if err != nil {
		return []DNSAnswer{}, errors.New("Failed to connect to the server")
	}
	defer conn.Close()

	ans := DNSExchangeConn(conn, name, qt)
	if len(ans) == 0 {
		return []DNSAnswer{}, errors.New("The query was unsuccessful")
	}
	return ans, nil
}

func ReverseDNSWithDialContext(dc dialCtx, ip string) (string, error) {
	var name string

	addr := ReverseIP(ip) + ".in-addr.arpa"
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

func textToTypeNum(text string) (uint16, error) {
	var qtype uint16

	switch text {
	case "CNAME":
		qtype = dns.TypeCNAME
	case "A":
		qtype = dns.TypeA
	case "AAAA":
		qtype = dns.TypeAAAA
	case "PTR":
		qtype = dns.TypePTR
	case "NS":
		qtype = dns.TypeNS
	case "MX":
		qtype = dns.TypeMX
	case "TXT":
		qtype = dns.TypeTXT
	case "SOA":
		qtype = dns.TypeSOA
	case "SPF":
		qtype = dns.TypeSPF
	case "SRV":
		qtype = dns.TypeSRV
	}

	if qtype == 0 {
		return qtype, errors.New("DNS message type not supported")
	}
	return qtype, nil
}

// DNSExchange - Encapsulates miekg/dns usage
func DNSExchangeConn(conn net.Conn, name string, qtype uint16) []DNSAnswer {
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
	co.WriteMsg(m)
	// Set the maximum time for receiving the answer
	co.SetReadDeadline(time.Now().Add(3 * time.Second))
	r, err := co.ReadMsg()
	if err != nil {
		return answers
	}
	// Check that the query was successful
	if r != nil && r.Rcode != dns.RcodeSuccess {
		return answers
	}

	data := extractRawData(r, qtype)

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

func extractRawData(msg *dns.Msg, qtype uint16) []string {
	var data []string

	for _, a := range msg.Answer {
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
	return data
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

func removeLastDot(name string) string {
	sz := len(name)

	if sz > 0 && name[sz-1] == '.' {
		return name[:sz-1]
	}
	return name
}
