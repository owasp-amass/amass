// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/utils"
	"github.com/miekg/dns"
)

// ResolveError contains the Rcode returned during the DNS query.
type ResolveError struct {
	Err   string
	Rcode int
}

func (e *ResolveError) Error() string {
	return e.Err
}

type resolveRequest struct {
	Timestamp time.Time
	Name      string
	Qtype     uint16
	Result    chan *resolveResult
}

func (r *Resolver) returnRequest(req *resolveRequest, res *resolveResult) {
	req.Result <- res
}

type resolveResult struct {
	Records []requests.DNSAnswer
	Again   bool
	Err     error
}

func makeResolveResult(rec []requests.DNSAnswer, again bool, err string, rcode int) *resolveResult {
	return &resolveResult{
		Records: rec,
		Again:   again,
		Err: &ResolveError{
			Err:   err,
			Rcode: rcode,
		},
	}
}

func randomInt(min, max int) int {
	return min + rand.Intn((max-min)+1)
}

// Resolver performs DNS queries on a single resolver at high-performance.
type Resolver struct {
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
	score          int
}

// NewResolver initializes a Resolver that send DNS queries to the IP address in the addr value.
func NewResolver(addr string) *Resolver {
	parts := strings.Split(addr, ":")
	if len(parts) == 1 && parts[0] == addr {
		addr += ":53"
	}

	d := &net.Dialer{}
	conn, err := d.Dial("udp", addr)
	if err != nil {
		return nil
	}

	r := &Resolver{
		Address:        addr,
		WindowDuration: 2 * time.Second,
		Dialer:         d,
		Conn:           conn,
		XchgQueue:      new(utils.Queue),
		XchgChan:       make(chan *resolveRequest, 1000),
		Xchgs:          make(map[uint16]*resolveRequest),
		Done:           make(chan struct{}, 2),
		rcodeStats:     make(map[int]int64),
		last:           time.Now(),
		successRate:    55 * time.Millisecond,
		score:          100,
	}
	go r.fillXchgChan()
	go r.checkForTimeouts()
	go r.monitorPerformance()
	go r.exchanges()
	return r
}

// Stop causes the Resolver to stop sending DNS queries and closes the network connection.
func (r *Resolver) Stop() {
	close(r.Done)
	time.Sleep(time.Second)
	r.Conn.Close()
}

// Available returns true if the Resolver can handle another DNS request.
func (r *Resolver) Available() bool {
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

// SanityCheck performs some basic checks to see if the Resolver will be usable.
func (r *Resolver) SanityCheck() bool {
	ch := make(chan bool, 10)
	f := func(name string, flip bool) {
		var err error
		again := true
		var success bool

		for i := 0; i < 2 && again; i++ {
			_, again, err = r.Resolve(name, "A")
			if err == nil {
				success = true
				break
			}
		}

		if flip {
			success = !success
		}
		ch <- success
	}

	// Check that valid names can be resolved
	goodNames := []string{
		"www.owasp.org",
		"twitter.com",
		"github.com",
		"www.google.com",
	}
	for _, name := range goodNames {
		go f(name, false)
	}

	// Check that invalid names do not return false positives
	badNames := []string{
		"not-a-real-name.owasp.org",
		"wwww.owasp.org",
		"www-1.owasp.org",
		"www1.owasp.org",
		"wwww.google.com",
		"www-1.google.com",
		"www1.google.com",
		"not-a-real-name.google.com",
	}
	for _, name := range badNames {
		go f(name, true)
	}

	l := len(goodNames) + len(badNames)
	for i := 0; i < l; i++ {
		select {
		case success := <-ch:
			if !success {
				return false
			}
		}
	}
	return true
}

// Resolve is performs DNS queries using the Resolver.
func (r *Resolver) Resolve(name, qtype string) ([]requests.DNSAnswer, bool, error) {
	qt, err := textToTypeNum(qtype)
	if err != nil {
		return nil, false, &ResolveError{
			Err:   err.Error(),
			Rcode: 100,
		}
	}

	resultChan := make(chan *resolveResult)
	r.XchgQueue.Append(&resolveRequest{
		Name:   name,
		Qtype:  qt,
		Result: resultChan,
	})
	result := <-resultChan
	return result.Records, result.Again, result.Err
}

// ReverseDNS is performs reverse DNS queries using the Resolver.
func (r *Resolver) ReverseDNS(addr string) (string, string, error) {
	var name, ptr string

	if ip := net.ParseIP(addr); utils.IsIPv4(ip) {
		ptr = utils.ReverseIP(addr) + ".in-addr.arpa"
	} else if utils.IsIPv6(ip) {
		ptr = utils.IPv6NibbleFormat(utils.HexString(ip)) + ".ip6.arpa"
	} else {
		return ptr, "", &ResolveError{
			Err:   fmt.Sprintf("Invalid IP address parameter: %s", addr),
			Rcode: 100,
		}
	}

	answers, _, err := r.Resolve(ptr, "PTR")
	if err != nil {
		return ptr, name, err
	}

	for _, a := range answers {
		if a.Type == 12 {
			name = RemoveLastDot(a.Data)
			break
		}
	}

	if name == "" {
		err = &ResolveError{
			Err:   fmt.Sprintf("PTR record not found for IP address: %s", addr),
			Rcode: 100,
		}
	} else if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		err = &ResolveError{
			Err:   fmt.Sprintf("Invalid target in PTR record answer: %s", name),
			Rcode: 100,
		}
	}
	return ptr, name, err
}

func (r *Resolver) currentScore() int {
	r.RLock()
	defer r.RUnlock()

	return r.score
}

func (r *Resolver) reduceScore() {
	r.Lock()
	defer r.Unlock()

	r.score--
}

func (r *Resolver) getSuccessRate() time.Duration {
	r.RLock()
	defer r.RUnlock()

	return r.successRate
}

func (r *Resolver) setSuccessRate(d time.Duration) {
	r.Lock()
	defer r.Unlock()

	r.successRate = d
}

func (r *Resolver) getID() uint16 {
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

func (r *Resolver) queueRequest(id uint16, req *resolveRequest) {
	r.XchgsLock.Lock()
	r.Xchgs[id] = req
	r.XchgsLock.Unlock()
}

func (r *Resolver) pullRequest(id uint16) *resolveRequest {
	r.XchgsLock.Lock()
	defer r.XchgsLock.Unlock()

	res := r.Xchgs[id]
	delete(r.Xchgs, id)
	return res
}

func (r *Resolver) checkForTimeouts() {
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

func (r *Resolver) fillXchgChan() {
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
func (r *Resolver) exchanges() {
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

func (r *Resolver) writeMessage(co *dns.Conn, req *resolveRequest) {
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

func (r *Resolver) readMessages(co *dns.Conn, msgs chan *dns.Msg) {
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

func (r *Resolver) tcpExchange(req *resolveRequest) {
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

func (r *Resolver) processMessage(msg *dns.Msg) {
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

	var answers []requests.DNSAnswer
	for _, a := range extractRawData(msg, req.Qtype) {
		answers = append(answers, requests.DNSAnswer{
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

func (r *Resolver) monitorPerformance() {
	var successes, attempts int64

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	m := time.NewTicker(time.Minute)
	defer m.Stop()
	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			successes, attempts = r.calcSuccessRate(successes, attempts)
		case <-m.C:
			successes = 0
			attempts = 0
			r.wipeStats()
			r.wipeAttempts()
			r.wipeTimeouts()
			if r.getSuccessRate() > 50*time.Millisecond {
				r.setSuccessRate(50 * time.Millisecond)
			}
		}
	}
}

func (r *Resolver) updateStats(rcode int) {
	r.Lock()
	defer r.Unlock()

	r.rcodeStats[rcode] = r.rcodeStats[rcode] + 1
}

func (r *Resolver) wipeStats() {
	r.Lock()
	defer r.Unlock()

	for k := range r.rcodeStats {
		r.rcodeStats[k] = 0
	}
}

func (r *Resolver) updatesAttempts() {
	r.Lock()
	defer r.Unlock()

	r.attempts++
}

func (r *Resolver) wipeAttempts() {
	r.Lock()
	defer r.Unlock()

	r.attempts = 0
}

func (r *Resolver) updateTimeouts(t int) {
	r.Lock()
	defer r.Unlock()

	r.timeouts += int64(t)
}

func (r *Resolver) wipeTimeouts() {
	r.Lock()
	defer r.Unlock()

	r.timeouts = 0
}

func (r *Resolver) calcSuccessRate(prevSuc, prevAtt int64) (successes, attempts int64) {
	r.RLock()
	successes = r.rcodeStats[dns.RcodeSuccess]
	successes += r.rcodeStats[dns.RcodeFormatError]
	successes += r.rcodeStats[dns.RcodeNameError]
	successes += r.rcodeStats[dns.RcodeYXDomain]
	successes += r.rcodeStats[dns.RcodeNotAuth]
	successes += r.rcodeStats[dns.RcodeNotZone]
	attempts = r.attempts
	curRate := r.successRate
	r.RUnlock()

	attemptDelta := attempts - prevAtt
	if attemptDelta < 10 {
		return
	}

	successDelta := successes - prevSuc
	if successDelta <= 0 {
		r.reduceScore()
		r.setSuccessRate(curRate + (25 * time.Millisecond))
		return
	}

	ratio := float64(successDelta) / float64(attemptDelta)
	if ratio < 0.25 || curRate > (500*time.Millisecond) {
		r.reduceScore()
		r.setSuccessRate(curRate + (25 * time.Millisecond))
	} else if ratio > 0.75 && (curRate >= (15 * time.Millisecond)) {
		r.setSuccessRate(curRate - (10 * time.Millisecond))
	} else {
		r.setSuccessRate(curRate + (10 * time.Millisecond))
	}
	return
}
