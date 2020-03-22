// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/queue"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/miekg/dns"
)

// The priority levels for DNS resolution.
const (
	PriorityLow int = iota
	PriorityHigh
	PriorityCritical
)

// Index values into the Resolver.Stats map.
const (
	QueryAttempts    = 64
	QueryTimeouts    = 65
	QueryRTT         = 66
	QueryCompletions = 67
)

// ResolverErrRcode is our made up rcode to indicate an interface error.
const ResolverErrRcode = 100

// TimeoutRcode is our made up rcode to indicate that a query timed out.
const TimeoutRcode = 101

// NotAvailableRcode is our made up rcode to indicate an availability problem.
const NotAvailableRcode = 256

const (
	defaultWindowDuration = 500 * time.Millisecond
	defaultConnRotation   = 30 * time.Second
)

// RetryCodes are the rcodes that cause the resolver to suggest trying again.
var RetryCodes = []int{
	TimeoutRcode,
	dns.RcodeRefused,
	dns.RcodeServerFailure,
	dns.RcodeNotImplemented,
}

// ResolveError contains the Rcode returned during the DNS query.
type ResolveError struct {
	Err   string
	Rcode int
}

func (e *ResolveError) Error() string {
	return e.Err
}

type resolveRequest struct {
	ID        uint16
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
	// Address returns the IP address where the resolver is located
	Address() string

	// Port returns the port number used to communicate with the resolver
	Port() int

	// Resolve performs DNS queries using the Resolver
	Resolve(ctx context.Context, name, qtype string, priority int) ([]requests.DNSAnswer, bool, error)

	// Reverse is performs reverse DNS queries using the Resolver
	Reverse(ctx context.Context, addr string, priority int) (string, string, error)

	// Available returns true if the Resolver can handle another DNS request
	Available() (bool, error)

	// Stats returns performance counters
	Stats() map[int]int64
	WipeStats()

	// ReportError indicates to the Resolver that it delivered an erroneos response
	ReportError()

	// MatchesWildcard returns true if the request provided resolved to a DNS wildcard
	MatchesWildcard(ctx context.Context, req *requests.DNSRequest) bool

	// GetWildcardType returns the DNS wildcard type for the provided subdomain name
	GetWildcardType(ctx context.Context, req *requests.DNSRequest) int

	// SubdomainToDomain returns the first subdomain name of the provided
	// parameter that responds to a DNS query for the NS record type
	SubdomainToDomain(name string) string

	// Stop the Resolver
	Stop() error
	IsStopped() bool
}

// BaseResolver performs DNS queries on a single resolver at high-performance.
type BaseResolver struct {
	sync.RWMutex
	Done           chan struct{}
	WindowDuration time.Duration
	CurrentConn    net.Conn
	LastConn       net.Conn
	xchgQueues     []*queue.Queue
	xchgsLock      sync.RWMutex
	xchgs          map[uint16]*resolveRequest
	timeoutSlice   []uint16
	timeoutsLock   sync.Mutex
	address        string
	port           string
	stats          map[int]int64
	attempts       int64
	timeouts       int64
	numrtt         int64
	stopLock       sync.RWMutex
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
		Done:           make(chan struct{}, 2),
		WindowDuration: defaultWindowDuration,
		xchgQueues: []*queue.Queue{
			new(queue.Queue),
			new(queue.Queue),
			new(queue.Queue),
		},
		xchgs:   make(map[uint16]*resolveRequest),
		address: addr,
		port:    port,
		stats:   make(map[int]int64),
	}

	r.rotateConnections()
	go r.sendQueries()
	go r.checkForTimeouts()
	go r.readMessages(false)
	go r.readMessages(true)
	go r.periodicRotations()
	return r
}

// Stop causes the Resolver to stop sending DNS queries and closes the network connection.
func (r *BaseResolver) Stop() error {
	if r.IsStopped() {
		return nil
	}

	r.stopLock.Lock()
	r.stopped = true
	r.stopLock.Unlock()

	close(r.Done)
	if r.CurrentConn != nil {
		r.CurrentConn.Close()
	}
	if r.LastConn != nil {
		r.LastConn.Close()
	}
	return nil
}

// IsStopped implements the Resolver interface.
func (r *BaseResolver) IsStopped() bool {
	r.stopLock.RLock()
	defer r.stopLock.RUnlock()

	return r.stopped
}

// Address implements the Resolver interface.
func (r *BaseResolver) Address() string {
	return r.address
}

// Port implements the Resolver interface.
func (r *BaseResolver) Port() int {
	if p, err := strconv.Atoi(r.port); err == nil {
		return p
	}

	return 0
}

// Available always returns true.
func (r *BaseResolver) Available() (bool, error) {
	if r.IsStopped() {
		msg := fmt.Sprintf("DNS: Resolver %s has been stopped", r.Address())

		return false, &ResolveError{Err: msg}
	}

	return true, nil
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
	r.numrtt = 0
	for k := range r.stats {
		r.stats[k] = 0
	}
}

// ReportError indicates to the Resolver that it delivered an erroneos response.
func (r *BaseResolver) ReportError() {
	return
}

// MatchesWildcard returns true if the request provided resolved to a DNS wildcard.
func (r *BaseResolver) MatchesWildcard(ctx context.Context, req *requests.DNSRequest) bool {
	return false
}

// GetWildcardType returns the DNS wildcard type for the provided subdomain name.
func (r *BaseResolver) GetWildcardType(ctx context.Context, req *requests.DNSRequest) int {
	return WildcardTypeNone
}

// SubdomainToDomain returns the first subdomain name of the provided
// parameter that responds to a DNS query for the NS record type.
func (r *BaseResolver) SubdomainToDomain(name string) string {
	return name
}

func (r *BaseResolver) returnRequest(req *resolveRequest, res *resolveResult) {
	req.Result <- res
}

func (r *BaseResolver) periodicRotations() {
	t := time.NewTicker(defaultConnRotation)
	defer t.Stop()

	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			r.rotateConnections()
		}
	}
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

		r.CurrentConn, err = d.Dial("udp", r.address+":"+r.port)
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
func (r *BaseResolver) Resolve(ctx context.Context, name, qtype string, priority int) ([]requests.DNSAnswer, bool, error) {
	if priority != PriorityCritical && priority != PriorityHigh && priority != PriorityLow {
		return []requests.DNSAnswer{}, false, &ResolveError{
			Err:   fmt.Sprintf("Resolver: Invalid priority parameter: %d", priority),
			Rcode: ResolverErrRcode,
		}
	}

	if avail, err := r.Available(); !avail {
		return []requests.DNSAnswer{}, true, err
	}

	qt, err := textToTypeNum(qtype)
	if err != nil {
		return nil, false, &ResolveError{
			Err:   err.Error(),
			Rcode: ResolverErrRcode,
		}
	}

	var bus *eventbus.EventBus
	// Obtain the event bus reference and report the resolver activity
	if b := ctx.Value(requests.ContextEventBus); b != nil {
		bus = b.(*eventbus.EventBus)

		bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, "Resolver "+r.Address())
	}

	resultChan := make(chan *resolveResult, 2)
	// Use the correct queue based on the priority
	r.xchgQueues[priority].Append(&resolveRequest{
		Name:   name,
		Qtype:  qt,
		Result: resultChan,
	})
	result := <-resultChan

	r.Lock()
	r.stats[QueryCompletions] = r.stats[QueryCompletions] + 1
	r.Unlock()

	// Report the completion of the DNS query
	if bus != nil {
		rcode := dns.RcodeSuccess
		if result.Err != nil {
			rcode = (result.Err.(*ResolveError)).Rcode
		}

		bus.Publish(requests.ResolveCompleted, eventbus.PriorityCritical, time.Now(), rcode)
	}

	return result.Records, result.Again, result.Err
}

// Reverse is performs reverse DNS queries using the Resolver.
func (r *BaseResolver) Reverse(ctx context.Context, addr string, priority int) (string, string, error) {
	var name, ptr string

	if ip := net.ParseIP(addr); amassnet.IsIPv4(ip) {
		ptr = amassdns.ReverseIP(addr) + ".in-addr.arpa"
	} else if amassnet.IsIPv6(ip) {
		ptr = amassdns.IPv6NibbleFormat(ip.String()) + ".ip6.arpa"
	} else {
		return ptr, "", &ResolveError{
			Err:   fmt.Sprintf("Invalid IP address parameter: %s", addr),
			Rcode: ResolverErrRcode,
		}
	}

	answers, _, err := r.Resolve(ctx, ptr, "PTR", priority)
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
			Rcode: ResolverErrRcode,
		}
	} else if strings.HasSuffix(name, ".in-addr.arpa") || strings.HasSuffix(name, ".ip6.arpa") {
		err = &ResolveError{
			Err:   fmt.Sprintf("Invalid target in PTR record answer: %s", name),
			Rcode: ResolverErrRcode,
		}
	}
	return ptr, name, err
}

func (r *BaseResolver) checkForTimeouts() {
	t := time.NewTicker(r.WindowDuration)
	defer t.Stop()

	for {
		select {
		case <-r.Done:
			return
		case <-t.C:
			var count int
			var removals []uint16

			r.timeoutsLock.Lock()
			// Discover requests that have timed out and remove them from the map
			for _, id := range r.timeoutSlice {
				if req := r.pullRequestAfterTimeout(id, r.WindowDuration); req != nil {
					count++
					removals = append(removals, id)
					estr := fmt.Sprintf("DNS query on resolver %s, for %s type %d timed out",
						r.address, req.Name, req.Qtype)
					r.returnRequest(req, makeResolveResult(nil, true, estr, TimeoutRcode))
				}
			}
			r.timeoutsLock.Unlock()

			// Remove elements that timed out from the requests slice
			for _, id := range removals {
				r.delTimeoutFromSlice(id)
			}
			// Complete handling of the timed out requests
			r.updateTimeouts(count)
		}
	}
}

func (r *BaseResolver) sendQueries() {
	curIdx := 0
	maxIdx := 6
	delays := []int{5, 10, 15, 25, 50, 75, 100}

	for {
		select {
		case <-r.Done:
			return
		default:
			var sent bool
			// Pull from the critical queue first
			for count, p := 0, PriorityCritical; p >= PriorityLow && count < 100; p-- {
				for ; count < 100; count++ {
					element, found := r.xchgQueues[p].Next()
					if !found {
						break
					}

					curIdx = 0
					sent = true
					r.writeMessage(element.(*resolveRequest))
				}
			}

			if !sent {
				time.Sleep(time.Duration(delays[curIdx]) * time.Millisecond)
				if curIdx < maxIdx {
					curIdx++
				}
			}
		}
	}
}

func (r *BaseResolver) writeMessage(req *resolveRequest) {
	var co *dns.Conn
	msg := queryMessage(r.getID(), req.Name, req.Qtype)

	for {
		co = r.currentConnection()
		if co != nil {
			break
		}
		time.Sleep(250 * time.Millisecond)
	}

	co.SetWriteDeadline(time.Now().Add(r.WindowDuration))
	if err := co.WriteMsg(msg); err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS error: Failed to write query msg: %v", err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, TimeoutRcode))
		return
	}

	r.queueRequest(msg.MsgHdr.Id, req)
	r.updateAttempts()
}

func (r *BaseResolver) readMessages(last bool) {
loop:
	for {
		select {
		case <-r.Done:
			return
		default:
			var co *dns.Conn
			if last {
				co = r.lastConnection()
			} else {
				co = r.currentConnection()
			}

			if co == nil {
				time.Sleep(250 * time.Millisecond)
				continue loop
			}

			co.SetReadDeadline(time.Now().Add(r.WindowDuration))
			if read, err := co.ReadMsg(); err == nil && read != nil {
				go r.processMessage(read)
			}
		}
	}
}

func (r *BaseResolver) processMessage(m *dns.Msg) {
	req := r.pullRequest(m.MsgHdr.Id)
	if req == nil {
		return
	}

	r.updateRTT(time.Now().Sub(req.Timestamp))
	r.updateStats(m.Rcode)
	// Check that the query was successful
	if m.Rcode != dns.RcodeSuccess {
		var again bool
		for _, code := range RetryCodes {
			if m.Rcode == code {
				again = true
				break
			}
		}
		estr := fmt.Sprintf("DNS query on resolver %s, for %s type %d returned error %s",
			r.address, req.Name, req.Qtype, dns.RcodeToString[m.Rcode])
		r.returnRequest(req, makeResolveResult(nil, again, estr, m.Rcode))
		return
	}

	if m.Truncated {
		r.tcpExchange(m.MsgHdr.Id, req)
		return
	}

	r.finishProcessing(m, req)
}

func (r *BaseResolver) finishProcessing(m *dns.Msg, req *resolveRequest) {
	var answers []requests.DNSAnswer

	for _, a := range extractRawData(m, req.Qtype) {
		answers = append(answers, requests.DNSAnswer{
			Name: req.Name,
			Type: int(req.Qtype),
			TTL:  0,
			Data: strings.TrimSpace(a),
		})
	}

	if len(answers) == 0 {
		estr := fmt.Sprintf("DNS query on resolver %s, for %s type %d returned 0 records",
			r.address, req.Name, req.Qtype)
		r.returnRequest(req, makeResolveResult(nil, false, estr, m.Rcode))
		return
	}

	r.returnRequest(req, &resolveResult{
		Records: answers,
		Again:   false,
		Err:     nil,
	})
}

func (r *BaseResolver) tcpExchange(id uint16, req *resolveRequest) {
	var d net.Dialer
	msg := queryMessage(id, req.Name, req.Qtype)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn, err := d.DialContext(ctx, "tcp", r.address+":"+r.port)
	if err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS: Failed to obtain TCP connection to %s:%s: %v", r.address, r.port, err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, NotAvailableRcode))
		return
	}
	defer conn.Close()

	co := &dns.Conn{Conn: conn}
	co.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if err := co.WriteMsg(msg); err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS error: Failed to write query msg: %v", err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, TimeoutRcode))
		return
	}

	co.SetReadDeadline(time.Now().Add(10 * time.Second))
	read, err := co.ReadMsg()
	if read == nil || err != nil {
		r.pullRequest(msg.MsgHdr.Id)
		estr := fmt.Sprintf("DNS error: Failed to read the reply msg: %v", err)
		r.returnRequest(req, makeResolveResult(nil, true, estr, TimeoutRcode))
		return
	}

	r.finishProcessing(read, req)
}

func (r *BaseResolver) updateTimeouts(t int) {
	r.Lock()
	defer r.Unlock()

	r.stats[QueryTimeouts] = r.stats[QueryTimeouts] + int64(t)
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

func (r *BaseResolver) getID() uint16 {
	r.xchgsLock.Lock()
	defer r.xchgsLock.Unlock()

	var id uint16
	for {
		id = dns.Id()
		if _, found := r.xchgs[id]; !found {
			r.xchgs[id] = &resolveRequest{Timestamp: time.Now()}
			break
		}
	}
	return id
}

func (r *BaseResolver) queueRequest(id uint16, req *resolveRequest) {
	req.ID = id
	req.Timestamp = time.Now()

	r.xchgsLock.Lock()
	r.xchgs[id] = req
	r.xchgsLock.Unlock()

	r.addTimeoutToSlice(id)
}

func (r *BaseResolver) pullRequest(id uint16) *resolveRequest {
	r.delTimeoutFromSlice(id)

	r.xchgsLock.Lock()
	defer r.xchgsLock.Unlock()

	req := r.xchgs[id]
	delete(r.xchgs, id)

	return req
}

func (r *BaseResolver) pullRequestAfterTimeout(id uint16, timeout time.Duration) *resolveRequest {
	r.xchgsLock.Lock()
	defer r.xchgsLock.Unlock()

	if req, found := r.xchgs[id]; found && time.Now().After(req.Timestamp.Add(timeout)) {
		delete(r.xchgs, id)
		return req
	}

	return nil
}

func (r *BaseResolver) updateRequestTimeout(id uint16, timeout time.Time) {
	r.xchgsLock.Lock()
	defer r.xchgsLock.Unlock()

	if req, found := r.xchgs[id]; found {
		req.Timestamp = timeout
	}
}

func (r *BaseResolver) addTimeoutToSlice(id uint16) {
	r.timeoutsLock.Lock()
	defer r.timeoutsLock.Unlock()

	r.timeoutSlice = append(r.timeoutSlice, id)
}

func (r *BaseResolver) delTimeoutFromSlice(id uint16) {
	r.timeoutsLock.Lock()
	defer r.timeoutsLock.Unlock()

	var n int
	// Remove the element identified by id
	for _, i := range r.timeoutSlice {
		if i != id {
			r.timeoutSlice[n] = i
			n++
		}
	}
	r.timeoutSlice = r.timeoutSlice[:n]
}
