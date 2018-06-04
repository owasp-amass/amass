// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"errors"
	"fmt"
	"math/rand"
	"net"
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

	// Ensures we do not resolve names more than once
	inFilter map[string]struct{}

	// Ensures we do not send out names more than once
	outFilter map[string]struct{}

	// Data collected about various subdomains
	subdomains map[string]map[int][]string

	// Domains discovered by the SubdomainToDomain method call
	domains map[string]struct{}

	// The channel that accepts new AmassRequests for the subdomain manager
	subMgrIn chan *AmassRequest

	// Requests are sent through this channel to check DNS wildcard matches
	wildcardReq chan *wildcard
}

func NewDNSService(config *AmassConfig) *DNSService {
	ds := &DNSService{
		inFilter:    make(map[string]struct{}),
		outFilter:   make(map[string]struct{}),
		subdomains:  make(map[string]map[int][]string),
		domains:     make(map[string]struct{}),
		subMgrIn:    make(chan *AmassRequest, 50),
		wildcardReq: make(chan *wildcard, 50),
	}

	ds.BaseAmassService = *NewBaseAmassService("DNS Service", config, ds)
	return ds
}

func (ds *DNSService) OnStart() error {
	ds.BaseAmassService.OnStart()

	go ds.subdomainManager()
	go ds.processRequests()
	go ds.processWildcardMatches()
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
		case <-t.C:
			go ds.performDNSRequest()
		case <-check.C:
			ds.SetActive(false)
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

	req := ds.NextRequest()
	// Plow through the requests that are not of interest
	for req != nil && (req.Name == "" || ds.duplicate(req.Name) ||
		ds.Config().Blacklisted(req.Name) || req.Domain == "") {
		req = ds.NextRequest()
	}
	if req == nil {
		return
	}
	ds.SetActive(true)
	// Make multiple attempts based on source of the name
	num := attemptsByTag(req.Tag)
	for i := 0; i < num; i++ {
		// Query a DNS server for the new name
		answers, err = nameToRecords(req.Name)
		if err == nil {
			break
		}
		time.Sleep(ds.Config().Frequency)
	}
	// If the name did not resolve, we are finished
	if err != nil {
		return
	}
	req.Records = answers

	if req.Tag != SCRAPE && ds.DetectWildcard(req) {
		return
	}
	// Return the successfully resolved names + address
	for _, record := range answers {
		name := removeLastDot(record.Name)

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
			Records: answers,
			Tag:     tag,
			Source:  source,
		}
	}
}

func nameToRecords(name string) ([]DNSAnswer, error) {
	var answers []DNSAnswer

	ans, err := ResolveDNS(name, "CNAME")
	if err == nil {
		answers = append(answers, ans[0])
		return answers, nil
	}

	ans, err = ResolveDNS(name, "PTR")
	if err == nil {
		answers = append(answers, ans[0])
		return answers, nil
	}

	ans, err = ResolveDNS(name, "A")
	if err == nil {
		answers = append(answers, ans...)
	}

	ans, err = ResolveDNS(name, "AAAA")
	if err == nil {
		answers = append(answers, ans...)
	}

	if len(answers) == 0 {
		return nil, fmt.Errorf("No records resolved for the name: %s", name)
	}
	return answers, nil
}

func (ds *DNSService) SubdomainToDomain(name string) string {
	ds.Lock()
	defer ds.Unlock()

	var domain string

	// Obtain all parts of the subdomain name
	labels := strings.Split(strings.TrimSpace(name), ".")
	// Check the cache for all parts of the name
	for i := len(labels); i >= 0; i-- {
		sub := strings.Join(labels[i:], ".")

		if _, ok := ds.domains[sub]; ok {
			domain = sub
			break
		}
	}
	// If the root domain was in the cache, return it now
	if domain != "" {
		return domain
	}
	// Check the DNS for all parts of the name
	for i := len(labels) - 2; i >= 0; i-- {
		sub := strings.Join(labels[i:], ".")

		if _, err := ResolveDNS(sub, "NS"); err == nil {
			ds.domains[sub] = struct{}{}
			domain = sub
			break
		}
	}
	return domain
}

//--------------------------------------------------------------------------------------------------
// DNS wildcard detection implementation

type wildcard struct {
	Req *AmassRequest
	Ans chan bool
}

type dnsWildcard struct {
	HasWildcard bool
	Answers     []DNSAnswer
}

// DetectWildcard - Checks subdomains in the wildcard cache for matches on the IP address
func (ds *DNSService) DetectWildcard(req *AmassRequest) bool {
	answer := make(chan bool, 2)

	ds.wildcardReq <- &wildcard{
		Req: req,
		Ans: answer,
	}
	return <-answer
}

// Goroutine that keeps track of DNS wildcards discovered
func (ds *DNSService) processWildcardMatches() {
	wildcards := make(map[string]*dnsWildcard)

	for {
		select {
		case wr := <-ds.wildcardReq:
			wr.Ans <- ds.matchesWildcard(wr.Req, wildcards)
		}
	}
}

func (ds *DNSService) matchesWildcard(req *AmassRequest, wildcards map[string]*dnsWildcard) bool {
	var answer bool

	name := req.Name
	root := req.Domain

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
				if a := ds.wildcardDetection(sub); a != nil {
					entry.HasWildcard = true
					entry.Answers = append(entry.Answers, a...)
				}
			}
			w = entry
			wildcards[sub] = w
		}
		// Check if the subdomain and address in question match a wildcard
		if w.HasWildcard && compareAnswers(req.Records, w.Answers) {
			answer = true
		}
	}
	return answer
}

func compareAnswers(ans1, ans2 []DNSAnswer) bool {
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

// wildcardDetection detects if a domain returns an IP
// address for "bad" names, and if so, which address(es) are used
func (ds *DNSService) wildcardDetection(sub string) []DNSAnswer {
	var answers []DNSAnswer

	name := unlikelyName(sub)
	if name == "" {
		return nil
	}
	// Check if the name resolves
	a, err := ResolveDNS(name, "CNAME")
	if err == nil {
		answers = append(answers, a...)
	}

	a, err = ResolveDNS(name, "A")
	if err == nil {
		answers = append(answers, a...)
	}

	a, err = ResolveDNS(name, "AAAA")
	if err == nil {
		answers = append(answers, a...)
	}

	if len(answers) == 0 {
		return nil
	}
	return answers
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

//--------------------------------------------------------------------------------------------------
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
	// The subdomain manager is now done with it
	ds.sendOut(req)
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
	if num-1 < len(strings.Split(req.Domain, ".")) {
		return
	}

	if !ds.Config().IsDomainInScope(req.Name) {
		return
	}
	// Some scrapers can discover new names using subdomains
	if sub != req.Domain {
		ds.Config().scrape.SendRequest(&AmassRequest{
			Name:   sub,
			Domain: req.Domain,
		})
	}
	// Does this subdomain have a wildcard?
	if ds.DetectWildcard(req) {
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

func (ds *DNSService) basicQueries(subdomain, domain string) {
	var answers []DNSAnswer

	// Obtain the DNS answers for the NS records related to the domain
	ans, err := ResolveDNS(subdomain, "NS")
	if err == nil {
		for _, a := range ans {
			if ds.Config().Active {
				go ds.zoneTransfer(subdomain, domain, a.Data)
			}

			answers = append(answers, a)
		}
	}
	// Obtain the DNS answers for the MX records related to the domain
	ans, err = ResolveDNS(subdomain, "MX")
	if err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	}
	// Obtain the DNS answers for the TXT records related to the domain
	ans, err = ResolveDNS(subdomain, "TXT")
	if err == nil {
		answers = append(answers, ans...)
	}
	// Obtain the DNS answers for the SOA records related to the domain
	ans, err = ResolveDNS(subdomain, "SOA")
	if err == nil {
		answers = append(answers, ans...)
	}

	ds.sendOut(&AmassRequest{
		Name:    subdomain,
		Domain:  domain,
		Records: answers,
		Tag:     "dns",
		Source:  "Forward DNS",
	})
}

func (ds *DNSService) queryServiceNames(subdomain, domain string) {
	var answers []DNSAnswer

	// Check all the popular SRV records
	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		ans, err := ResolveDNS(srvName, "SRV")
		if err == nil {
			answers = append(answers, ans...)
		}
		// Do not go too fast
		time.Sleep(ds.Config().Frequency)
	}

	ds.sendOut(&AmassRequest{
		Name:    subdomain,
		Domain:  domain,
		Records: answers,
		Tag:     "dns",
		Source:  "Forward DNS",
	})
}

func (ds *DNSService) sendOut(req *AmassRequest) {
	ds.Config().data.SendRequest(req)
	ds.Config().alt.SendRequest(req)
	ds.Config().archive.SendRequest(req)
	ds.Config().brute.SendRequest(req)
}

func (ds *DNSService) zoneTransfer(sub, domain, server string) {
	a, err := ResolveDNS(server, "A")
	if err != nil {
		return
	}
	addr := a[0].Data

	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	conn, err := DialContext(ctx, "tcp", addr+":53")
	if err != nil {
		return
	}
	defer conn.Close()

	xfr := &dns.Transfer{
		Conn:        &dns.Conn{Conn: conn},
		ReadTimeout: 10 * time.Second,
	}

	m := &dns.Msg{}
	m.SetAxfr(dns.Fqdn(sub))

	in, err := xfr.In(m, "")
	if err != nil {
		return
	}

	for en := range in {
		names := getXfrNames(en)
		if names == nil {
			continue
		}

		for _, name := range names {
			n := name[:len(name)-1]

			ds.SendRequest(&AmassRequest{
				Name:   n,
				Domain: domain,
				Tag:    "axfr",
				Source: "DNS ZoneXFR",
			})
		}
	}
}

func getXfrNames(en *dns.Envelope) []string {
	var names []string

	if en.Error != nil {
		return nil
	}

	for _, a := range en.RR {
		var name string

		switch v := a.(type) {
		case *dns.A:
			name = v.Hdr.Name
		case *dns.AAAA:
			name = v.Hdr.Name
		case *dns.NS:
			name = v.Ns
		case *dns.CNAME:
			name = v.Hdr.Name
		case *dns.SRV:
			name = v.Hdr.Name
		case *dns.TXT:
			name = v.Hdr.Name
		default:
			continue
		}

		names = append(names, name)
	}
	return names
}

//-------------------------------------------------------------------------------------------------
// All usage of the miekg/dns package

func ResolveDNS(name, qtype string) ([]DNSAnswer, error) {
	qt, err := textToTypeNum(qtype)
	if err != nil {
		return []DNSAnswer{}, err
	}
	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	conn, err := DNSDialContext(ctx, "udp", "")
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

func ReverseDNS(ip string) (string, error) {
	var name string

	addr := ReverseIP(ip) + ".in-addr.arpa"
	answers, err := ResolveDNS(addr, "PTR")
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
