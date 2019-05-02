// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/miekg/dns"
)

// The priority levels for DNS resolution.
const (
	PriorityLow int = iota
	PriorityHigh
	PriorityCritical
)

var (
	// Public & free DNS servers
	publicResolvers = []string{
		"1.1.1.1:53",     // Cloudflare
		"8.8.8.8:53",     // Google
		"64.6.64.6:53",   // Verisign
		"77.88.8.8:53",   // Yandex.DNS
		"74.82.42.42:53", // Hurricane Electric
		"1.0.0.1:53",     // Cloudflare Secondary
		"8.8.4.4:53",     // Google Secondary
		"9.9.9.10:53",    // Quad9 Secondary
		"64.6.65.6:53",   // Verisign Secondary
		"77.88.8.1:53",   // Yandex.DNS Secondary
	}

	resolvers []*resolver

	retryCodes = []int{
		dns.RcodeRefused,
		dns.RcodeServerFailure,
		dns.RcodeNotImplemented,
	}

	maxRetries = 3
)

func init() {
	for _, addr := range publicResolvers {
		resolvers = append(resolvers, newResolver(addr))
	}
}

type resolveError struct {
	Err   string
	Rcode int
}

func (e *resolveError) Error() string {
	return e.Err
}

type resolveRequest struct {
	Timestamp time.Time
	Name      string
	Qtype     uint16
	Result    chan *resolveResult
}

func (r *resolver) returnRequest(req *resolveRequest, res *resolveResult) {
	req.Result <- res
}

type resolveResult struct {
	Records []core.DNSAnswer
	Again   bool
	Err     error
}

func makeResolveResult(rec []core.DNSAnswer, again bool, err string, rcode int) *resolveResult {
	return &resolveResult{
		Records: rec,
		Again:   again,
		Err: &resolveError{
			Err:   err,
			Rcode: rcode,
		},
	}
}

type resolver struct {
	sync.RWMutex
	Address        string
	WindowDuration time.Duration
	Dialer         *net.Dialer
	Conn           net.Conn
	XchgQueue      *utils.Queue
	XchgChan       chan *resolveRequest
	XchgsLock      sync.Mutex
	Xchgs          map[uint16]*resolveRequest
	Done           chan struct{}
	rcodeStats     map[int]int64
	attempts       int64
	timeouts       int64
	last           time.Time
	successRate    time.Duration
}

func newResolver(addr string) *resolver {
	d := &net.Dialer{}
	conn, err := d.Dial("udp", addr)
	if err != nil {
		return nil
	}

	r := &resolver{
		Address:        addr,
		WindowDuration: 2 * time.Second,
		Dialer:         d,
		Conn:           conn,
		XchgQueue:      utils.NewQueue(),
		XchgChan:       make(chan *resolveRequest, 1000),
		Xchgs:          make(map[uint16]*resolveRequest),
		Done:           make(chan struct{}, 2),
		rcodeStats:     make(map[int]int64),
		last:           time.Now(),
		successRate:    10 * time.Millisecond,
	}
	go r.fillXchgChan()
	go r.checkForTimeouts()
	go r.monitorPerformance()
	go r.exchanges()
	return r
}

func (r *resolver) stop() {
	close(r.Done)
	time.Sleep(time.Second)
	r.Conn.Close()
}

func (r *resolver) getID() uint16 {
	r.XchgsLock.Lock()
	defer r.XchgsLock.Unlock()

	var id uint16
	for {
		id = dns.Id()
		if _, found := r.Xchgs[id]; !found {
			r.Xchgs[id] = new(resolveRequest)
			break
		}
	}
	return id
}

func (r *resolver) queueRequest(id uint16, req *resolveRequest) {
	r.XchgsLock.Lock()
	r.Xchgs[id] = req
	r.XchgsLock.Unlock()
}

func (r *resolver) pullRequest(id uint16) *resolveRequest {
	r.XchgsLock.Lock()
	defer r.XchgsLock.Unlock()

	res := r.Xchgs[id]
	delete(r.Xchgs, id)
	return res
}

func (r *resolver) checkForTimeouts() {
	t := time.NewTicker(r.WindowDuration)
	defer t.Stop()
	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			now := time.Now()
			var timeouts []uint16

			// Discover requests that have timed out
			r.XchgsLock.Lock()
			for id, req := range r.Xchgs {
				if req.Name != "" && now.After(req.Timestamp.Add(r.WindowDuration)) {
					timeouts = append(timeouts, id)
				}
			}
			r.XchgsLock.Unlock()
			// Remove the timed out requests from the map
			for _, id := range timeouts {
				if req := r.pullRequest(id); req != nil {
					estr := fmt.Sprintf("DNS query for %s, type %d timed out", req.Name, req.Qtype)
					r.returnRequest(req, makeResolveResult(nil, true, estr, 100))
				}
			}
			// Complete handling of the timed out requests
			r.updateTimeouts(len(timeouts))
		}
	}
}

func (r *resolver) resolve(name string, qtype uint16) ([]core.DNSAnswer, bool, error) {
	resultChan := make(chan *resolveResult)
	r.XchgQueue.Append(&resolveRequest{
		Name:   name,
		Qtype:  qtype,
		Result: resultChan,
	})
	result := <-resultChan
	return result.Records, result.Again, result.Err
}

func (r *resolver) fillXchgChan() {
	curIdx := 0
	maxIdx := 7
	delays := []int{10, 25, 50, 75, 100, 150, 250, 500}
	for {
		select {
		case <-r.Done:
			return
		default:
			element, ok := r.XchgQueue.Next()
			if !ok {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
				continue
			}
			curIdx = 0
			r.XchgChan <- element.(*resolveRequest)
		}
	}
}

// exchanges encapsulates miekg/dns usage
func (r *resolver) exchanges() {
	co := &dns.Conn{Conn: r.Conn}
	msgs := make(chan *dns.Msg, 2000)

	go r.readMessages(co, msgs)
	for {
		select {
		case <-r.Done:
			return
		case read := <-msgs:
			go r.processMessage(read)
		case req := <-r.XchgChan:
			go r.writeMessage(co, req)
		}
	}
}

func (r *resolver) writeMessage(co *dns.Conn, req *resolveRequest) {
	msg := queryMessage(r.getID(), req.Name, req.Qtype)

	co.SetWriteDeadline(time.Now().Add(r.WindowDuration))
	if err := co.WriteMsg(msg); err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS error: Failed to write query msg: %v", err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, 100))
		return
	}

	req.Timestamp = time.Now()
	r.queueRequest(msg.MsgHdr.Id, req)
	r.updatesAttempts()
}

func (r *resolver) readMessages(co *dns.Conn, msgs chan *dns.Msg) {
	for {
		select {
		case <-r.Done:
			return
		default:
			if read, err := co.ReadMsg(); err == nil && read != nil {
				msgs <- read
			}
		}
	}
}

func (r *resolver) tcpExchange(req *resolveRequest) {
	msg := queryMessage(r.getID(), req.Name, req.Qtype)
	d := net.Dialer{Timeout: r.WindowDuration}

	conn, err := d.Dial("tcp", r.Address)
	if err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS: Failed to obtain TCP connection to %s: %v", r.Address, err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, 100))
		return
	}
	defer conn.Close()

	co := &dns.Conn{Conn: conn}
	co.SetWriteDeadline(time.Now().Add(r.WindowDuration))
	if err := co.WriteMsg(msg); err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS error: Failed to write query msg: %v", err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, 100))
		return
	}

	req.Timestamp = time.Now()
	r.queueRequest(msg.MsgHdr.Id, req)
	co.SetReadDeadline(time.Now().Add(r.WindowDuration))
	read, err := co.ReadMsg()
	if read == nil || err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS error: Failed to read the reply msg: %v", err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, 100))
		return
	}

	r.processMessage(read)
}

func (r *resolver) processMessage(msg *dns.Msg) {
	req := r.pullRequest(msg.MsgHdr.Id)
	if req == nil {
		return
	}
	r.updateStats(msg.Rcode)
	// Check that the query was successful
	if msg.Rcode != dns.RcodeSuccess {
		var again bool
		for _, code := range retryCodes {
			if msg.Rcode == code {
				again = true
				break
			}
		}
		estr := fmt.Sprintf("DNS query for %s, type %d returned error %s",
			req.Name, req.Qtype, dns.RcodeToString[msg.Rcode])
		r.returnRequest(req, makeResolveResult(nil, again, estr, msg.Rcode))
		return
	}

	if msg.Truncated {
		go r.tcpExchange(req)
		return
	}

	var answers []core.DNSAnswer
	for _, a := range extractRawData(msg, req.Qtype) {
		answers = append(answers, core.DNSAnswer{
			Name: req.Name,
			Type: int(req.Qtype),
			TTL:  0,
			Data: strings.TrimSpace(a),
		})
	}

	if len(answers) == 0 {
		estr := fmt.Sprintf("DNS query for %s, type %d returned 0 records", req.Name, req.Qtype)
		r.returnRequest(req, makeResolveResult(nil, false, estr, msg.Rcode))
		return
	}

	r.returnRequest(req, &resolveResult{
		Records: answers,
		Again:   false,
		Err:     nil,
	})
}

func (r *resolver) monitorPerformance() {
	var successes int64

	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			successes = r.calcSuccessRate(successes, time.Second)
		}
	}
}

func (r *resolver) updateStats(rcode int) {
	r.Lock()
	defer r.Unlock()

	r.rcodeStats[rcode] = r.rcodeStats[rcode] + 1
}

func (r *resolver) updatesAttempts() {
	r.Lock()
	defer r.Unlock()

	r.attempts++
}

func (r *resolver) updateTimeouts(t int) {
	r.Lock()
	defer r.Unlock()

	r.timeouts += int64(t)

}

func (r *resolver) calcSuccessRate(prevSuc int64, tSize time.Duration) (successes int64) {
	r.RLock()
	successes = r.rcodeStats[dns.RcodeSuccess]
	successes += r.rcodeStats[dns.RcodeFormatError]
	successes += r.rcodeStats[dns.RcodeNameError]
	successes += r.rcodeStats[dns.RcodeYXDomain]
	successes += r.rcodeStats[dns.RcodeNotAuth]
	successes += r.rcodeStats[dns.RcodeNotZone]
	r.RUnlock()

	rate := tSize
	successDelta := successes - prevSuc
	if successDelta > 0 {
		rate = tSize / time.Duration(successDelta)
	}
	// Cannot get too slow
	min := 100 * time.Millisecond
	if rate > min {
		rate = min
	}

	r.Lock()
	r.successRate = rate
	r.Unlock()
	return
}

func (r *resolver) Available() bool {
	var avail bool

	r.Lock()
	if time.Now().After(r.last.Add(r.successRate)) {
		r.last = time.Now()
		avail = true
	}
	r.Unlock()
	// There needs to be an opportunity to exceed the success rate
	if !avail {
		if random := randomInt(1, 100); random <= 5 {
			avail = true
		}
	}
	return avail
}

func nextResolver() *resolver {
	var attempts int
	max := len(resolvers)
	for {
		rnd := rand.Int()
		r := resolvers[rnd%len(resolvers)]

		if r.Available() {
			return r
		}

		attempts++
		if attempts <= max {
			continue
		}

		for _, r := range resolvers {
			if r.Available() {
				return r
			}
		}
		attempts = 0
		time.Sleep(time.Duration(randomInt(100, 1000)) * time.Millisecond)
	}
}

func randomInt(min, max int) int {
	return min + rand.Intn((max-min)+1)
}

// SetCustomResolvers modifies the set of resolvers used during enumeration.
func SetCustomResolvers(res []string) {
	if len(res) <= 0 {
		return
	}

	for _, r := range resolvers {
		r.stop()
	}
	resolvers = []*resolver{}

	for _, r := range res {
		addr := r

		parts := strings.Split(addr, ":")
		if len(parts) == 1 && parts[0] == addr {
			addr += ":53"
		}
		resolvers = append(resolvers, newResolver(addr))
	}
}

// Resolve allows all components to make DNS requests without using the DNSService object.
func Resolve(name, qtype string, priority int) ([]core.DNSAnswer, error) {
	qt, err := textToTypeNum(qtype)
	if err != nil {
		return nil, &resolveError{
			Err:   err.Error(),
			Rcode: 100,
		}
	}

	var maxattempts, maxservfail int
	switch priority {
	case PriorityHigh:
		maxattempts = 50
		maxservfail = 10
	case PriorityLow:
		maxattempts = 25
		maxservfail = 6
	}

	var again bool
	start := time.Now()
	var ans []core.DNSAnswer
	var attempts, servfail int
	for {
		ans, again, err = nextResolver().resolve(name, qt)
		if !again {
			break
		} else if priority == PriorityCritical {
			continue
		}

		attempts++
		if attempts > maxattempts && time.Now().After(start.Add(2*time.Minute)) {
			break
		}
		// Do not allow server failure errors to continue as long
		if (err.(*resolveError)).Rcode == dns.RcodeServerFailure {
			servfail++
			if servfail > maxservfail && time.Now().After(start.Add(time.Minute)) {
				break
			} else if servfail <= (maxservfail / 2) {
				time.Sleep(time.Duration(randomInt(3000, 5000)) * time.Millisecond)
			}
		}
	}
	return ans, err
}

// Reverse is performs reverse DNS queries without using the DNSService object.
func Reverse(addr string) (string, string, error) {
	var name, ptr string

	if ip := net.ParseIP(addr); utils.IsIPv4(ip) {
		ptr = utils.ReverseIP(addr) + ".in-addr.arpa"
	} else if utils.IsIPv6(ip) {
		ptr = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".ip6.arpa"
	} else {
		return ptr, "", &resolveError{
			Err:   fmt.Sprintf("Invalid IP address parameter: %s", addr),
			Rcode: 100,
		}
	}

	answers, err := Resolve(ptr, "PTR", PriorityLow)
	if err != nil {
		return ptr, name, err
	}

	for _, a := range answers {
		if a.Type == 12 {
			name = removeLastDot(a.Data)
			break
		}
	}

	if name == "" {
		err = &resolveError{
			Err:   fmt.Sprintf("PTR record not found for IP address: %s", addr),
			Rcode: 100,
		}
	} else if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		err = &resolveError{
			Err:   fmt.Sprintf("Invalid target in PTR record answer: %s", name),
			Rcode: 100,
		}
	}
	return ptr, name, err
}

func queryMessage(id uint16, name string, qtype uint16) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
			Id:                id,
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
	return m
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

// ZoneTransfer attempts a DNS zone transfer using the server identified in the parameters.
// The returned slice contains all the records discovered from the zone transfer.
func ZoneTransfer(sub, domain, server string) ([]*core.Request, error) {
	var results []*core.Request

	addr, err := nameserverAddr(server)
	if addr == "" {
		return results, fmt.Errorf("DNS server has no A or AAAA record: %s: %v", server, err)
	}

	// Set the maximum time allowed for making the connection
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "tcp", addr+":53")
	if err != nil {
		return results, fmt.Errorf("Zone xfr error: Failed to obtain TCP connection to %s: %v", addr+":53", err)
	}
	defer conn.Close()

	xfr := &dns.Transfer{
		Conn:        &dns.Conn{Conn: conn},
		ReadTimeout: 30 * time.Second,
	}

	m := &dns.Msg{}
	m.SetAxfr(dns.Fqdn(sub))

	in, err := xfr.In(m, "")
	if err != nil {
		return results, fmt.Errorf("DNS zone transfer error: %s: %v", addr+":53", err)
	}

	for en := range in {
		reqs := getXfrRequests(en, domain)
		if reqs == nil {
			continue
		}

		for _, r := range reqs {
			results = append(results, r)
		}
	}
	return results, nil
}

// NsecTraversal attempts to retrieve a DNS zone using NSEC-walking.
func NsecTraversal(domain, server string) ([]*core.Request, error) {
	var results []*core.Request

	addr, err := nameserverAddr(server)
	if addr == "" {
		return results, fmt.Errorf("DNS server has no A or AAAA record: %s: %v", server, err)
	}

	d := &net.Dialer{}
	conn, err := d.Dial("udp", addr + ":53")
	if err != nil {
		return results, fmt.Errorf("Failed to setup UDP connection with the DNS server: %s: %v", server, err)
	}
	defer conn.Close()
	co := &dns.Conn{Conn: conn}

	re := utils.SubdomainRegex(domain)
loop:
	for next := domain; next != ""; {
		name := next
		next = ""
		for _, attempt := range walkAttempts(name, domain) {
			id := dns.Id()
			msg := walkMsg(id, attempt, dns.TypeA)

			co.SetWriteDeadline(time.Now().Add(2 * time.Second))
			if err := co.WriteMsg(msg); err != nil {
				continue
			}

			co.SetReadDeadline(time.Now().Add(2 * time.Second))
			in, err := co.ReadMsg()
			if err != nil || in == nil || in.MsgHdr.Id != id {
				continue
			}

			for _, rr := range in.Answer {
				if rr.Header().Rrtype != dns.TypeA {
					continue
				}

				n := strings.ToLower(removeLastDot(rr.Header().Name))
				results = append(results, &core.Request{
					Name: n,
					Domain: domain,
					Tag: core.DNS,
					Source: "NSEC Walk",
				})

				if _, ok := rr.(*dns.NSEC); ok {
					next = rr.(*dns.NSEC).NextDomain
					continue loop
				}
			}

			for _, rr := range in.Ns {
				if rr.Header().Rrtype != dns.TypeNSEC {
					continue
				}

				prev := strings.ToLower(removeLastDot(rr.Header().Name))
				nn := walkHostPart(name, domain)
				hp := walkHostPart(prev, domain)
				if !re.MatchString(prev) || hp >= nn {
					continue
				}

				results = append(results, &core.Request{
					Name: prev,
					Domain: domain,
					Tag: core.DNS,
					Source: "NSEC Walk",
				})

				n := strings.ToLower(removeLastDot(rr.(*dns.NSEC).NextDomain))
				hn := walkHostPart(n, domain)
				if n != "" && nn < hn {
					next = n
					continue loop
				}
			}
		}
	}
	return results, nil
}

func walkAttempts(name, domain string) []string {
	name = strings.ToLower(name)
	domain = strings.ToLower(domain)

	// The original subdomain name and another with a zero label prepended
	attempts := []string{name, "0." + name}
	if name == domain {
		return attempts
	}

	host := walkHostPart(name, domain)
	// A hyphen appended to the hostname portion + the domain name
	attempts = append(attempts, host + "-." + domain)

	rhost := []rune(host)
	last := string(rhost[len(rhost)-1])
	// The last character of the hostname portion duplicated/appended
	return append(attempts, host + last + "." + domain)
}

func walkHostPart(name, domain string) string {
	dlen := len(strings.Split(domain, "."))
	parts := strings.Split(name, ".")
	
	return strings.Join(parts[0:len(parts) - dlen], ".")
}

func walkMsg(id uint16, name string, qtype uint16) *dns.Msg {
	m := &dns.Msg{
		MsgHdr: dns.MsgHdr{
			Authoritative:     false,
			AuthenticatedData: false,
			CheckingDisabled:  false,
			RecursionDesired:  true,
			Opcode:            dns.OpcodeQuery,
			Id:                id,
			Rcode:             dns.RcodeSuccess,
		},
		Question: make([]dns.Question, 1),
	}
	m.Question[0] = dns.Question{
		Name:   dns.Fqdn(name),
		Qtype:  qtype,
		Qclass: uint16(dns.ClassINET),
	}
	opt := &dns.OPT{
		Hdr: dns.RR_Header{
			Name:   ".",
			Rrtype: dns.TypeOPT,
		},
	}
	opt.SetDo()
	opt.SetUDPSize(dns.DefaultMsgSize)
	m.Extra = append(m.Extra, opt)
	return m
}

func nameserverAddr(server string) (string, error) {
	a, err := Resolve(server, "A", PriorityHigh)
	if err != nil {
		a, err = Resolve(server, "AAAA", PriorityHigh)
		if err != nil {
			return "", err
		}
	}
	return a[0].Data, nil
}

//-------------------------------------------------------------------------------------------------
// Support functions
//-------------------------------------------------------------------------------------------------

func getXfrRequests(en *dns.Envelope, domain string) []*core.Request {
	if en.Error != nil {
		return nil
	}

	reqs := make(map[string]*core.Request)
	for _, a := range en.RR {
		var record core.DNSAnswer

		switch v := a.(type) {
		case *dns.CNAME:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeCNAME)
			record.Data = removeLastDot(v.Target)
		case *dns.A:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeA)
			record.Data = v.A.String()
		case *dns.AAAA:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeAAAA)
			record.Data = v.AAAA.String()
		case *dns.PTR:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypePTR)
			record.Data = removeLastDot(v.Ptr)
		case *dns.NS:
			record.Name = realName(v.Hdr)
			record.Type = int(dns.TypeNS)
			record.Data = removeLastDot(v.Ns)
		case *dns.MX:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeMX)
			record.Data = removeLastDot(v.Mx)
		case *dns.TXT:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeTXT)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SOA:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeSOA)
			record.Data = v.Ns + " " + v.Mbox
		case *dns.SPF:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeSPF)
			for _, piece := range v.Txt {
				record.Data += piece + " "
			}
		case *dns.SRV:
			record.Name = removeLastDot(v.Hdr.Name)
			record.Type = int(dns.TypeSRV)
			record.Data = removeLastDot(v.Target)
		default:
			continue
		}

		if r, found := reqs[record.Name]; found {
			r.Records = append(r.Records, record)
		} else {
			reqs[record.Name] = &core.Request{
				Name:    record.Name,
				Domain:  domain,
				Records: []core.DNSAnswer{record},
				Tag:     core.AXFR,
				Source:  "DNS Zone XFR",
			}
		}
	}

	var requests []*core.Request
	for _, r := range reqs {
		requests = append(requests, r)
	}
	return requests
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
		return qtype, fmt.Errorf("DNS message type '%s' not supported", text)
	}
	return qtype, nil
}

func extractRawData(msg *dns.Msg, qtype uint16) []string {
	var data []string

	for _, a := range msg.Answer {
		if a.Header().Rrtype == qtype {
			var value string

			switch qtype {
			case dns.TypeA:
				if t, ok := a.(*dns.A); ok {
					value = utils.CopyString(t.A.String())
				}
			case dns.TypeAAAA:
				if t, ok := a.(*dns.AAAA); ok {
					value = utils.CopyString(t.AAAA.String())
				}
			case dns.TypeCNAME:
				if t, ok := a.(*dns.CNAME); ok {
					value = utils.CopyString(t.Target)
				}
			case dns.TypePTR:
				if t, ok := a.(*dns.PTR); ok {
					value = utils.CopyString(t.Ptr)
				}
			case dns.TypeNS:
				if t, ok := a.(*dns.NS); ok {
					value = realName(t.Hdr) + "," + removeLastDot(t.Ns)
				}
			case dns.TypeMX:
				if t, ok := a.(*dns.MX); ok {
					value = utils.CopyString(t.Mx)
				}
			case dns.TypeTXT:
				if t, ok := a.(*dns.TXT); ok {
					for _, piece := range t.Txt {
						value += piece + " "
					}
				}
			case dns.TypeSOA:
				if t, ok := a.(*dns.SOA); ok {
					value = t.Ns + " " + t.Mbox
				}
			case dns.TypeSPF:
				if t, ok := a.(*dns.SPF); ok {
					for _, piece := range t.Txt {
						value += piece + " "
					}
				}
			case dns.TypeSRV:
				if t, ok := a.(*dns.SRV); ok {
					value = utils.CopyString(t.Target)
				}
			}

			if value != "" {
				data = append(data, strings.TrimSpace(value))
			}
		}
	}
	return data
}

func realName(hdr dns.RR_Header) string {
	pieces := strings.Split(hdr.Name, " ")

	return removeLastDot(pieces[len(pieces)-1])
}
