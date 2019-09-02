// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"fmt"
	"net"
	"strings"
	"sync"
	"time"

	amassnet "github.com/OWASP/Amass/net"
	"github.com/OWASP/Amass/queue"
	"github.com/OWASP/Amass/requests"
	"github.com/miekg/dns"
)

// Index values into the Resolver.Stats map
const (
	QueryAttempts = 64
	QueryTimeout  = 65
	QueryRTT      = 66
)

const (
	defaultWindowDuration = 2 * time.Second
	defaultConnRotation   = 30 * time.Second
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

// Resolver is the object type for performing DNS resolutions.
type Resolver interface {
	// Resolve performs DNS queries using the Resolver
	Resolve(name, qtype string) ([]requests.DNSAnswer, bool, error)

	// Reverse is performs reverse DNS queries using the Resolver
	Reverse(addr string) (string, string, error)

	// Available returns true if the Resolver can handle another DNS request
	Available() bool

	// Stats returns performance counters
	Stats() map[int]int64
	WipeStats()

	// ReportError indicates to the Resolver that it delivered an erroneos response
	ReportError()

	// Stop the Resolver
	Stop() error
}

// BaseResolver performs DNS queries on a single resolver at high-performance.
type BaseResolver struct {
	sync.RWMutex
	Address        string
	Port           string
	WindowDuration time.Duration
	CurrentConn    net.Conn
	LastConn       net.Conn
	XchgQueue      *queue.Queue
	XchgChan       chan *resolveRequest
	XchgsLock      sync.Mutex
	Xchgs          map[uint16]*resolveRequest
	Done           chan struct{}
	stats          map[int]int64
	attempts       int64
	timeouts       int64
	avgrtt         int64
	numrtt         int64
	stopped        bool
}

// NewBaseResolver initializes a Resolver that send DNS queries to the provided IP address.
func NewBaseResolver(addr string) *BaseResolver {
	port := "53"
	parts := strings.Split(addr, ":")
	if len(parts) == 2 {
		addr = parts[0]
		port = parts[1]
	}

	r := &BaseResolver{
		Address:        addr,
		Port:           port,
		WindowDuration: defaultWindowDuration,
		XchgQueue:      new(queue.Queue),
		XchgChan:       make(chan *resolveRequest, 1000),
		Xchgs:          make(map[uint16]*resolveRequest),
		Done:           make(chan struct{}, 2),
		stats:          make(map[int]int64),
	}

	r.rotateConnections()
	go r.fillXchgChan()
	go r.checkForTimeouts()
	go r.exchanges()
	return r
}

// Stop causes the Resolver to stop sending DNS queries and closes the network connection.
func (r *BaseResolver) Stop() error {
	if r.stopped {
		return nil
	}

	r.stopped = true
	close(r.Done)
	if r.CurrentConn != nil {
		r.CurrentConn.Close()
	}
	if r.LastConn != nil {
		r.LastConn.Close()
	}
	return nil
}

// Available always returns true.
func (r *BaseResolver) Available() bool {
	if r.stopped {
		return false
	}
	return true
}

// Stats returns performance counters.
func (r *BaseResolver) Stats() map[int]int64 {
	c := make(map[int]int64)

	r.RLock()
	defer r.RUnlock()

	for k, v := range r.stats {
		c[k] = v
	}
	return c
}

// WipeStats clears the performance counters.
func (r *BaseResolver) WipeStats() {
	r.Lock()
	defer r.Unlock()

	r.attempts = 0
	r.timeouts = 0
	r.avgrtt = 0
	r.numrtt = 0
	for k := range r.stats {
		r.stats[k] = 0
	}
}

// ReportError indicates to the Resolver that it delivered an erroneos response.
func (r *BaseResolver) ReportError() {
	return
}

func (r *BaseResolver) returnRequest(req *resolveRequest, res *resolveResult) {
	req.Result <- res
}

func (r *BaseResolver) rotateConnections() {
	r.Lock()
	defer r.Unlock()

	if r.LastConn != nil {
		r.LastConn.Close()
	}
	r.LastConn = r.CurrentConn

	var err error
	for {
		d := &net.Dialer{}

		r.CurrentConn, err = d.Dial("udp", r.Address+":"+r.Port)
		if err == nil {
			break
		}
		time.Sleep(time.Duration(randomInt(1, 10)) * time.Millisecond)
	}
}

func (r *BaseResolver) currentConnection() *dns.Conn {
	r.RLock()
	defer r.RUnlock()

	if r.CurrentConn == nil {
		return nil
	}
	return &dns.Conn{Conn: r.CurrentConn}
}

func (r *BaseResolver) lastConnection() *dns.Conn {
	r.RLock()
	defer r.RUnlock()

	if r.LastConn == nil {
		return nil
	}
	return &dns.Conn{Conn: r.LastConn}
}

// Resolve performs DNS queries using the Resolver.
func (r *BaseResolver) Resolve(name, qtype string) ([]requests.DNSAnswer, bool, error) {
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

// Reverse is performs reverse DNS queries using the Resolver.
func (r *BaseResolver) Reverse(addr string) (string, string, error) {
	var name, ptr string

	if ip := net.ParseIP(addr); amassnet.IsIPv4(ip) {
		ptr = amassnet.ReverseIP(addr) + ".in-addr.arpa"
	} else if amassnet.IsIPv6(ip) {
		ptr = amassnet.IPv6NibbleFormat(amassnet.HexString(ip)) + ".ip6.arpa"
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

func (r *BaseResolver) getID() uint16 {
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

func (r *BaseResolver) queueRequest(id uint16, req *resolveRequest) {
	r.XchgsLock.Lock()
	r.Xchgs[id] = req
	r.XchgsLock.Unlock()
}

func (r *BaseResolver) pullRequest(id uint16) *resolveRequest {
	r.XchgsLock.Lock()
	defer r.XchgsLock.Unlock()

	res := r.Xchgs[id]
	delete(r.Xchgs, id)
	return res
}

func (r *BaseResolver) checkForTimeouts() {
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
					estr := fmt.Sprintf("DNS query on resolver %s, for %s type %d timed out",
						r.Address, req.Name, req.Qtype)
					r.returnRequest(req, makeResolveResult(nil, true, estr, 100))
				}
			}
			// Complete handling of the timed out requests
			r.updateTimeouts(len(timeouts))
		}
	}
}

func (r *BaseResolver) fillXchgChan() {
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
func (r *BaseResolver) exchanges() {
	msgs := make(chan *dns.Msg, 2000)

	go r.readMessages(msgs, false)
	go r.readMessages(msgs, true)

	t := time.NewTicker(defaultConnRotation)
	defer t.Stop()
	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			go r.rotateConnections()
		case read := <-msgs:
			go r.processMessage(read)
		case req := <-r.XchgChan:
			go r.writeMessage(req)
		}
	}
}

func (r *BaseResolver) writeMessage(req *resolveRequest) {
	co := r.currentConnection()
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
	r.updateAttempts()
}

func (r *BaseResolver) readMessages(msgs chan *dns.Msg, last bool) {
loop:
	for {
		select {
		case <-r.Done:
			return
		default:
			co := r.currentConnection()
			if last {
				co = r.lastConnection()
			}

			if co == nil {
				time.Sleep(time.Second)
				continue loop
			}

			if read, err := co.ReadMsg(); err == nil && read != nil {
				msgs <- read
			}
		}
	}
}

func (r *BaseResolver) tcpExchange(req *resolveRequest) {
	msg := queryMessage(r.getID(), req.Name, req.Qtype)
	d := net.Dialer{Timeout: r.WindowDuration}

	conn, err := d.Dial("tcp", r.Address+":"+r.Port)
	if err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS: Failed to obtain TCP connection to %s: %v", r.Address+":"+r.Port, err)
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

func (r *BaseResolver) processMessage(msg *dns.Msg) {
	req := r.pullRequest(msg.MsgHdr.Id)
	if req == nil {
		return
	}

	r.updateRTT(time.Now().Sub(req.Timestamp))
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
		estr := fmt.Sprintf("DNS query on resolver %s, for %s type %d returned error %s",
			r.Address, req.Name, req.Qtype, dns.RcodeToString[msg.Rcode])
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
		estr := fmt.Sprintf("DNS query on resolver %s, for %s type %d returned 0 records",
			r.Address, req.Name, req.Qtype)
		r.returnRequest(req, makeResolveResult(nil, false, estr, msg.Rcode))
		return
	}

	r.returnRequest(req, &resolveResult{
		Records: answers,
		Again:   false,
		Err:     nil,
	})
}

func (r *BaseResolver) updateTimeouts(t int) {
	r.Lock()
	defer r.Unlock()

	r.stats[QueryTimeout] = r.stats[QueryTimeout] + int64(t)
}

func (r *BaseResolver) updateAttempts() {
	r.Lock()
	defer r.Unlock()

	r.stats[QueryAttempts] = r.stats[QueryAttempts] + 1
}

func (r *BaseResolver) updateRTT(rtt time.Duration) {
	r.Lock()
	defer r.Unlock()

	r.numrtt++
	avg := r.stats[QueryRTT]

	avg = avg + ((int64(rtt) - avg) / r.numrtt)
	r.stats[QueryRTT] = avg
}

func (r *BaseResolver) updateStats(rcode int) {
	r.Lock()
	defer r.Unlock()

	r.stats[rcode] = r.stats[rcode] + 1
}
