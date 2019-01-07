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

	"github.com/OWASP/Amass/amass/utils"
	"github.com/miekg/dns"
)

const (
	// NumOfResolutions is equal to the maximum queries to
	// be sent to a single resolver at any given moment
	NumOfResolutions int = 1000000
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
		"77.88.8.1:53",   // Yandex.DNS Secondary
	}

	resolvers []*resolver
)

func init() {
	for _, addr := range publicResolvers {
		resolvers = append(resolvers, newResolver(addr))
	}
}

type resolveRequest struct {
	Timestamp time.Time
	Name      string
	Qtype     uint16
	Result    chan *resolveResult
}

type resolveResult struct {
	Records []DNSAnswer
	Again   bool
	Err     error
}

type resolver struct {
	sync.Mutex
	Address        string
	MaxResolutions utils.Semaphore
	ExchangeTimes  chan time.Time
	ErrorTimes     chan time.Time
	WindowDuration time.Duration
	Dialer         *net.Dialer
	Conn           net.Conn
	XchgChan       chan *resolveRequest
	Xchgs          map[uint16]*resolveRequest
	Done           chan struct{}
}

func newResolver(addr string) *resolver {
	d := &net.Dialer{}
	conn, err := d.Dial("udp", addr)
	if err != nil {
		return nil
	}

	r := &resolver{
		Address:        addr,
		MaxResolutions: utils.NewSimpleSemaphore(NumOfResolutions),
		ExchangeTimes:  make(chan time.Time, int(float32(NumOfResolutions)*1.5)),
		ErrorTimes:     make(chan time.Time, int(float32(NumOfResolutions)*1.5)),
		WindowDuration: time.Second,
		Dialer:         d,
		Conn:           conn,
		XchgChan:       make(chan *resolveRequest, NumOfResolutions),
		Xchgs:          make(map[uint16]*resolveRequest),
		Done:           make(chan struct{}),
	}
	go r.monitorPerformance()
	go r.checkForTimeouts()
	go r.exchanges()
	return r
}

func (r *resolver) stop() {
	close(r.Done)
	time.Sleep(time.Second)
	r.Conn.Close()
}

func (r *resolver) queueRequest(id uint16, req *resolveRequest) {
	r.Lock()
	r.Xchgs[id] = req
	r.Unlock()
}

func (r *resolver) pullRequest(id uint16) *resolveRequest {
	var res *resolveRequest

	r.Lock()
	res = r.Xchgs[id]
	delete(r.Xchgs, id)
	r.Unlock()
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
			var ids []uint16
			var timeouts []*resolveRequest

			r.Lock()
			for key, req := range r.Xchgs {
				if now.After(req.Timestamp.Add(r.WindowDuration)) {
					ids = append(ids, key)
					timeouts = append(timeouts, req)
				}
			}

			for _, id := range ids {
				delete(r.Xchgs, id)
			}
			r.Unlock()

			for _, req := range timeouts {
				r.ErrorTimes <- now
				req.Result <- &resolveResult{
					Records: nil,
					Again:   true,
					Err:     fmt.Errorf("DNS query for %s, type %d timed out", req.Name, req.Qtype),
				}
			}
		}
	}
}

func (r *resolver) resolve(name string, qtype uint16) ([]DNSAnswer, bool, error) {
	defer r.MaxResolutions.Release(1)

	resultChan := make(chan *resolveResult)
	r.XchgChan <- &resolveRequest{
		Name:   name,
		Qtype:  qtype,
		Result: resultChan,
	}

	result := <-resultChan
	return result.Records, result.Again, result.Err
}

// exchanges encapsulates miekg/dns usage
func (r *resolver) exchanges() {
	co := &dns.Conn{Conn: r.Conn}
	msgs := make(chan *dns.Msg, NumOfResolutions)
	go r.readMessages(co, msgs)

	for {
		select {
		case <-r.Done:
			return
		case req := <-r.XchgChan:
			msg := queryMessage(req.Name, req.Qtype)
			r.ExchangeTimes <- time.Now()

			co.SetWriteDeadline(time.Now().Add(r.WindowDuration))
			if err := co.WriteMsg(msg); err != nil {
				r.ErrorTimes <- time.Now()
				req.Result <- &resolveResult{
					Records: nil,
					Again:   true,
					Err:     fmt.Errorf("DNS error: Failed to write query msg: %v", err),
				}
				continue
			}
			req.Timestamp = time.Now()
			r.queueRequest(msg.MsgHdr.Id, req)
		case read := <-msgs:
			req := r.pullRequest(read.MsgHdr.Id)
			if req == nil {
				continue
			}
			// Check that the query was successful
			if read.Rcode != dns.RcodeSuccess {
				again := true
				if read.Rcode == 3 {
					again = false
				}
				req.Result <- &resolveResult{
					Records: nil,
					Again:   again,
					Err: fmt.Errorf(
						"DNS query for %s, type %d returned error %d",
						req.Name, req.Qtype, read.Rcode),
				}
				continue
			}

			var answers []DNSAnswer
			for _, a := range extractRawData(read, req.Qtype) {
				answers = append(answers, DNSAnswer{
					Name: req.Name,
					Type: int(req.Qtype),
					TTL:  0,
					Data: strings.TrimSpace(a),
				})
			}
			if len(answers) == 0 {
				req.Result <- &resolveResult{
					Records: nil,
					Again:   false,
					Err:     fmt.Errorf("DNS query for %s, type %d returned 0 records", req.Name, req.Qtype),
				}
				continue
			}
			req.Result <- &resolveResult{
				Records: answers,
				Again:   false,
				Err:     nil,
			}
		}
	}
}

func (r *resolver) readMessages(co *dns.Conn, msgs chan *dns.Msg) {
	for {
		select {
		case <-r.Done:
			return
		default:
			rd, err := co.ReadMsg()
			if rd == nil || err != nil {
				r.ErrorTimes <- time.Now()
				continue
			}
			msgs <- rd
		}
	}
}

func (r *resolver) monitorPerformance() {
	var count int
	var xchgWin, errWin []time.Time

	// Start off with a reasonable load to the
	// network, and adjust based on performance
	count = NumOfResolutions - 1000
	r.MaxResolutions.Acquire(count)

	t := time.NewTicker(r.WindowDuration)
	defer t.Stop()

	for {
		select {
		case <-r.Done:
			return
		case xchg := <-r.ExchangeTimes:
			xchgWin = append(xchgWin, xchg)
		case err := <-r.ErrorTimes:
			errWin = append(errWin, err)
		case <-t.C:
			total := len(xchgWin)
			if total < 1000 {
				continue
			}
			// Check if we must reduce the number of simultaneous connections
			failures := len(errWin)
			potential := NumOfResolutions - count
			delta := 50
			alt := (NumOfResolutions - count) / 10
			if alt > delta {
				delta = alt
			}
			// Reduce if the percentage of timed out connections is too high
			if result := analyzeConnResults(total, failures); result == 1 {
				count -= delta
				r.MaxResolutions.Release(delta)
			} else if result == -1 && (potential-delta) > 0 {
				count += delta
				go r.MaxResolutions.Acquire(delta)
			}
			// Remove all the old slice elements
			xchgWin = []time.Time{}
			errWin = []time.Time{}
		}
	}
}

func analyzeConnResults(total, failures int) int {
	if failures == 0 {
		return 1
	}
	frac := float64(total) / float64(failures)
	if frac == 0 {
		return -1
	}
	percent := float64(100) / frac
	if percent >= 5.0 {
		return -1
	} else if percent < 5.0 {
		return 1
	}
	return 0
}

// nextResolver requests the next DNS resolution server
func nextResolver() *resolver {
	for {
		rnd := rand.Int()
		r := resolvers[rnd%len(resolvers)]

		if r.MaxResolutions.TryAcquire(1) {
			return r
		}
	}
}

// SetCustomResolvers modifies the set of resolvers used during enumeration
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

// Resolve allows all components to make DNS requests without using the DNSService object
func Resolve(name, qtype string) ([]DNSAnswer, error) {
	qt, err := textToTypeNum(qtype)
	if err != nil {
		return nil, err
	}

	tries := 3
	if qtype == "NS" || qtype == "MX" || qtype == "SOA" || qtype == "SPF" {
		tries = 7
	} else if qtype == "TXT" {
		tries = 10
	}

	var again bool
	var ans []DNSAnswer
	for i := 0; i < tries; i++ {
		r := nextResolver()

		ans, again, err = r.resolve(name, qt)
		if !again {
			break
		}
		time.Sleep(time.Duration(i) * time.Second)
	}
	return ans, err
}

// Reverse is performs reverse DNS queries without using the DNSService object
func Reverse(addr string) (string, string, error) {
	var name, ptr string

	ip := net.ParseIP(addr)
	if len(ip.To4()) == net.IPv4len {
		ptr = utils.ReverseIP(addr) + ".in-addr.arpa"
	} else if len(ip) == net.IPv6len {
		ptr = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".ip6.arpa"
	} else {
		return ptr, "", fmt.Errorf("Invalid IP address parameter: %s", addr)
	}

	answers, err := Resolve(ptr, "PTR")
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
		err = fmt.Errorf("PTR record not found for IP address: %s", addr)
	} else if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		err = fmt.Errorf("Invalid target in PTR record answer: %s", name)
	}
	return ptr, name, err
}

func queryMessage(name string, qtype uint16) *dns.Msg {
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
// The returned slice contains all the records discovered from the zone transfer
func ZoneTransfer(sub, domain, server string) ([]*Request, error) {
	var results []*Request

	a, err := Resolve(server, "A")
	if err != nil {
		a, err = Resolve(server, "AAAA")
		if err != nil {
			return results, fmt.Errorf("DNS server has no A or AAAA record: %s: %v", server, err)
		}
	}
	addr := a[0].Data

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
		ReadTimeout: 10 * time.Second,
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

//-------------------------------------------------------------------------------------------------
// Support functions
//-------------------------------------------------------------------------------------------------

func getXfrRequests(en *dns.Envelope, domain string) []*Request {
	if en.Error != nil {
		return nil
	}

	reqs := make(map[string]*Request)
	for _, a := range en.RR {
		var record DNSAnswer

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
			reqs[record.Name] = &Request{
				Name:    record.Name,
				Domain:  domain,
				Records: []DNSAnswer{record},
				Tag:     AXFR,
				Source:  "DNS Zone XFR",
			}
		}
	}

	var requests []*Request
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
			switch qtype {
			case dns.TypeA:
				if t, ok := a.(*dns.A); ok {
					data = append(data, utils.CopyString(t.A.String()))
				}
			case dns.TypeAAAA:
				if t, ok := a.(*dns.AAAA); ok {
					data = append(data, utils.CopyString(t.AAAA.String()))
				}
			case dns.TypeCNAME:
				if t, ok := a.(*dns.CNAME); ok {
					data = append(data, utils.CopyString(t.Target))
				}
			case dns.TypePTR:
				if t, ok := a.(*dns.PTR); ok {
					data = append(data, utils.CopyString(t.Ptr))
				}
			case dns.TypeNS:
				if t, ok := a.(*dns.NS); ok {
					data = append(data, realName(t.Hdr)+","+removeLastDot(t.Ns))
				}
			case dns.TypeMX:
				if t, ok := a.(*dns.MX); ok {
					data = append(data, utils.CopyString(t.Mx))
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
					data = append(data, utils.CopyString(t.Target))
				}
			}
		}
	}
	return data
}

func realName(hdr dns.RR_Header) string {
	pieces := strings.Split(hdr.Name, " ")

	return removeLastDot(pieces[len(pieces)-1])
}
