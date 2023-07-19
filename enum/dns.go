// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/resolve"
)

const (
	maxDNSQueryAttempts int           = 50
	maxRcodeServerFails int           = 3
	initialBackoffDelay time.Duration = 250 * time.Millisecond
	maximumBackoffDelay time.Duration = 4 * time.Second
)

// FwdQueryTypes include the DNS record types that are queried for a discovered name.
var FwdQueryTypes = []uint16{
	dns.TypeCNAME,
	dns.TypeA,
	dns.TypeAAAA,
}

var fwdQueryTypesLookup = map[uint16]int{dns.TypeCNAME: 0, dns.TypeA: 1, dns.TypeAAAA: 2}

type req struct {
	Ctx        context.Context
	Data       pipeline.Data
	Qtype      uint16
	Attempts   int
	Servfails  int
	InScope    bool
	Sent       bool
	HasRecords bool
}

// dnsTask is the task that handles all DNS name resolution requests within the pipeline.
type dnsTask struct {
	sync.Mutex
	once      sync.Once
	trust     string
	trusted   bool
	enum      *Enumeration
	done      chan struct{}
	pool      *resolve.Resolvers
	params    pipeline.TaskParams
	reqs      map[string]*req
	resps     chan *dns.Msg
	respQueue queue.Queue
	release   chan struct{}
}

// newDNSTask returns a dNSTask specific to the provided Enumeration.
func newDNSTask(e *Enumeration, trusted bool) *dnsTask {
	trust := "untrusted"
	pool := e.Sys.Resolvers()
	qps := e.Config.ResolversQPS
	if trusted {
		trust = "trusted"
		pool = e.Sys.TrustedResolvers()
		qps = e.Config.TrustedQPS
	}
	plen := pool.Len() * qps

	dt := &dnsTask{
		trust:     trust,
		trusted:   trusted,
		enum:      e,
		done:      make(chan struct{}, 2),
		pool:      pool,
		reqs:      make(map[string]*req),
		resps:     make(chan *dns.Msg, plen),
		respQueue: queue.NewQueue(),
		release:   make(chan struct{}, plen),
	}

	for i := 0; i < plen; i++ {
		dt.release <- struct{}{}
	}

	go dt.processResponses()
	go dt.moveResponsesToQueue()
	return dt
}

func (dt *dnsTask) stop() {
	select {
	case <-dt.done:
		return
	default:
	}
	close(dt.done)
	// TODO: empty the channel and queue to delete requests
}

func (dt *dnsTask) moveResponsesToQueue() {
	for {
		select {
		case <-dt.done:
			return
		case r := <-dt.resps:
			if r != nil {
				dt.respQueue.Append(r)
			}
		}
	}
}

func (dt *dnsTask) rootTaskFunc() pipeline.TaskFunc {
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		var r *requests.DNSRequest
		// Is this a root domain or proper subdomain name?
		switch v := data.(type) {
		case *requests.DNSRequest:
			if v.Domain != "" && v.Name == v.Domain {
				r = v.Clone().(*requests.DNSRequest)
			}
			// send the PTR records straight to the store stage
			if r != nil && (strings.HasSuffix(r.Name, ".in-addr.arpa") || strings.HasSuffix(r.Name, ".ip6.arpa")) {
				pipeline.SendData(ctx, "store", r, tp)
				return nil, nil
			}
		case *requests.SubdomainRequest:
			r = &requests.DNSRequest{
				Name:   v.Name,
				Domain: v.Domain,
			}
		}

		if r != nil && dt.enum.Config.IsDomainInScope(r.Name) {
			go dt.subdomainQueries(ctx, r, tp)
		}
		return data, nil
	})
}

// Process implements the pipeline Task interface.
func (dt *dnsTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	case <-dt.done:
		return nil, nil
	default:
	}

	dt.once.Do(func() {
		dt.Lock()
		dt.params = tp
		dt.Unlock()
	})

	if v, ok := data.(*requests.DNSRequest); ok {
		qtype := FwdQueryTypes[0]
		msg := resolve.QueryMsg(v.Name, qtype)
		k := key(msg.Id, msg.Question[0].Name)

		if dt.addReqWithIncrement(k, &req{
			Ctx:        ctx,
			Data:       data.Clone(),
			Qtype:      qtype,
			Attempts:   1,
			HasRecords: len(v.Records) > 0,
		}) {
			dt.pool.Query(ctx, msg, dt.resps)
		} else {
			dt.enum.Config.Log.Printf("Failed to enter %s into the request registry on the %s DNS task", msg.Question[0].Name, dt.trust)
		}
		return nil, nil
	}
	return data, nil
}

func (dt *dnsTask) nextStage(ctx context.Context, data pipeline.Data) {
	dt.Lock()
	params := dt.params
	dt.Unlock()

	if params == nil {
		return
	}

	stage := "validate"
	if dt.trusted {
		stage = "store"
	}

	pipeline.SendData(ctx, stage, data, params)
}

func key(id uint16, name string) string {
	return fmt.Sprintf("%d:%s", id, strings.ToLower(resolve.RemoveLastDot(name)))
}

func (dt *dnsTask) getReq(key string) *req {
	dt.Lock()
	defer dt.Unlock()

	if req, found := dt.reqs[key]; found {
		return req
	}
	return nil
}

func (dt *dnsTask) addReq(key string, entry *req) bool {
	dt.Lock()
	defer dt.Unlock()

	if _, found := dt.reqs[key]; !found {
		dt.reqs[key] = entry
		return true
	}
	return false
}

func (dt *dnsTask) addReqWithIncrement(key string, entry *req) bool {
	added := dt.addReq(key, entry)

	if added {
		<-dt.release
	}
	return added
}

func (dt *dnsTask) delReq(key string) *req {
	dt.Lock()
	defer dt.Unlock()

	if req, found := dt.reqs[key]; found {
		dt.reqs[key] = nil
		delete(dt.reqs, key)
		return req
	}
	return nil
}

func (dt *dnsTask) delReqWithDecrement(key string) {
	if req := dt.delReq(key); req != nil {
		dt.release <- struct{}{}

		if !req.Sent && (req.InScope || req.HasRecords) {
			dt.nextStage(req.Ctx, req.Data)
		}
	}
}

func (dt *dnsTask) processResponses() {
	for {
		select {
		case <-dt.done:
			return
		case <-dt.respQueue.Signal():
			if element, ok := dt.respQueue.Next(); ok {
				if msg, valid := element.(*dns.Msg); valid {
					dt.processResp(msg)
				}
			}
		}
	}
}

func (dt *dnsTask) processResp(resp *dns.Msg) {
	k := key(resp.Id, resp.Question[0].Name)

	entry := dt.getReq(k)
	if entry == nil {
		dt.enum.Config.Log.Printf("Failed to find %s in the request registry on the %s DNS task", resp.Question[0].Name, dt.trust)
		return
	}

	switch resp.Rcode {
	// check if the response indicates that the name doesn't exist
	case dns.RcodeNameError:
		dt.delReqWithDecrement(k)
		return
	// the rest are errors that should not continue across many resolvers
	case dns.RcodeFormatError:
		fallthrough
	case dns.RcodeServerFailure:
		fallthrough
	case dns.RcodeNotImplemented:
		fallthrough
	case dns.RcodeRefused:
		entry.Servfails++
	}

	ctx := entry.Ctx
	qtype := resp.Question[0].Qtype
	name := strings.ToLower(resolve.RemoveLastDot(resp.Question[0].Name))

	select {
	case <-ctx.Done():
		dt.delReqWithDecrement(k)
		return
	default:
	}

	switch v := entry.Data.(type) {
	case *requests.DNSRequest:
		if resp.Rcode == dns.RcodeSuccess {
			dt.processFwdRequest(ctx, resp, name, qtype, v, entry)
		} else {
			go dt.retry(resolve.QueryMsg(v.Name, qtype), resp.Id, entry)
		}
	default:
		dt.delReqWithDecrement(k)
	}
}

func (dt *dnsTask) retry(msg *dns.Msg, id uint16, entry *req) {
	k := key(id, msg.Question[0].Name)

	entry.Attempts++
	if entry.Attempts <= maxDNSQueryAttempts && entry.Servfails < maxRcodeServerFails {
		dt.delReq(k)
		dt.addReq(key(msg.Id, msg.Question[0].Name), entry)
		time.Sleep(resolve.TruncatedExponentialBackoff(entry.Attempts-1, initialBackoffDelay, maximumBackoffDelay))
		dt.pool.Query(entry.Ctx, msg, dt.resps)
	} else {
		dt.enum.Config.Log.Printf("%s was dropped after failing to resolve %d times on the %s DNS task", msg.Question[0].Name, entry.Attempts-1, dt.trust)
		dt.delReqWithDecrement(k)
	}
}

func (dt *dnsTask) nextType(ctx context.Context, name string, id, qtype uint16, entry *req) {
	k := key(id, name)

	if idx, found := fwdQueryTypesLookup[qtype]; found && idx+1 < len(FwdQueryTypes) {
		entry.Attempts = 1
		entry.Servfails = 0
		entry.Qtype = FwdQueryTypes[idx+1]
		msg := resolve.QueryMsg(name, entry.Qtype)
		dt.delReq(k)
		dt.addReq(key(msg.Id, msg.Question[0].Name), entry)
		dt.pool.Query(ctx, msg, dt.resps)
	} else {
		dt.delReqWithDecrement(k)
	}
}

func (dt *dnsTask) processFwdRequest(ctx context.Context, resp *dns.Msg, name string, qtype uint16, req *requests.DNSRequest, entry *req) {
	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		dt.nextType(ctx, name, resp.Id, qtype, entry)
		return
	}

	rr := resolve.AnswersByType(ans, qtype)
	if len(rr) == 0 {
		dt.nextType(ctx, name, resp.Id, qtype, entry)
		return
	}

	k := key(resp.Id, resp.Question[0].Name)
	if !dt.trusted {
		dt.nextStage(ctx, req)
		entry.Sent = true
		dt.delReqWithDecrement(k)
		return
	}

	if dt.enum.wildcardDetected(ctx, req, resp) {
		dt.delReqWithDecrement(k)
		return
	}

	req.Records = append(req.Records, convertAnswers(rr)...)
	entry.HasRecords = len(req.Records) > 0
	// are there additional record types to query for?
	if idx, found := fwdQueryTypesLookup[qtype]; found && qtype != dns.TypeCNAME && idx+1 < len(FwdQueryTypes) {
		dt.nextType(ctx, name, resp.Id, qtype, entry)
		return
	}
	// delReq will send the request to the next stage if it has records
	dt.delReqWithDecrement(k)
}

func (dt *dnsTask) subdomainQueries(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	ch := make(chan []requests.DNSAnswer, 4)

	go dt.queryNS(ctx, req.Name, req.Domain, ch, tp)
	go dt.queryMX(ctx, req.Name, ch, tp)
	go dt.querySOA(ctx, req.Name, ch, tp)
	go dt.querySPF(ctx, req.Name, ch, tp)

	for i := 0; i < 4; i++ {
		if rr := <-ch; rr != nil {
			req.Records = append(req.Records, rr...)
		}
	}

	if req.Valid() && len(req.Records) > 0 {
		pipeline.SendData(ctx, "store", req, tp)
	}
}

func (dt *dnsTask) queryNS(ctx context.Context, name, domain string, ch chan []requests.DNSAnswer, tp pipeline.TaskParams) {
	// Obtain the DNS answers for the NS records related to the domain
	if resp, err := dt.enum.dnsQuery(ctx, name, dns.TypeNS, dt.enum.Sys.TrustedResolvers(), maxDNSQueryAttempts); err == nil {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, dns.TypeNS); len(rr) > 0 {
				var records []requests.DNSAnswer

				for _, record := range rr {
					pipeline.SendData(ctx, "active", &requests.ZoneXFRRequest{
						Name:   name,
						Domain: domain,
						Server: record.Data,
					}, tp)
					records = append(records, convertAnswers([]*resolve.ExtractedAnswer{record})...)
				}

				ch <- records
				return
			}
		}
	}
	ch <- nil
}

func (dt *dnsTask) queryMX(ctx context.Context, name string, ch chan []requests.DNSAnswer, tp pipeline.TaskParams) {
	// Obtain the DNS answers for the MX records related to the domain
	if resp, err := dt.enum.dnsQuery(ctx, name, dns.TypeMX, dt.enum.Sys.TrustedResolvers(), maxDNSQueryAttempts); err == nil {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, dns.TypeMX); len(rr) > 0 {
				ch <- convertAnswers(rr)
				return
			}
		}
	}
	ch <- nil
}

func (dt *dnsTask) querySOA(ctx context.Context, name string, ch chan []requests.DNSAnswer, tp pipeline.TaskParams) {
	// Obtain the DNS answers for the SOA records related to the domain
	if resp, err := dt.enum.dnsQuery(ctx, name, dns.TypeSOA, dt.enum.Sys.TrustedResolvers(), maxDNSQueryAttempts); err == nil {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, dns.TypeSOA); len(rr) > 0 {
				var records []requests.DNSAnswer

				for _, a := range rr {
					pieces := strings.Split(a.Data, ",")
					a.Data = pieces[len(pieces)-1]
					records = append(records, convertAnswers([]*resolve.ExtractedAnswer{a})...)
				}
				ch <- records
			}
		}
	}
	ch <- nil
}

func (dt *dnsTask) querySPF(ctx context.Context, name string, ch chan []requests.DNSAnswer, tp pipeline.TaskParams) {
	// Obtain the DNS answers for the SPF records related to the domain
	if resp, err := dt.enum.dnsQuery(ctx, name, dns.TypeSPF, dt.enum.Sys.TrustedResolvers(), maxDNSQueryAttempts); err == nil {
		if ans := resolve.ExtractAnswers(resp); len(ans) > 0 {
			if rr := resolve.AnswersByType(ans, dns.TypeSPF); len(rr) > 0 {
				ch <- convertAnswers(rr)
				return
			}
		}
	}
	ch <- nil
}

func (e *Enumeration) fwdQuery(ctx context.Context, name string, qtype uint16) (*dns.Msg, error) {
	resp, err := e.dnsQuery(ctx, name, qtype, e.Sys.Resolvers(), maxDNSQueryAttempts)
	if err != nil {
		return resp, err
	}
	if resp == nil && err == nil {
		return nil, errors.New("query failed")
	}

	resp, err = e.dnsQuery(ctx, name, qtype, e.Sys.TrustedResolvers(), maxDNSQueryAttempts)
	if resp == nil && err == nil {
		err = errors.New("query failed")
	}
	return resp, err
}

func (e *Enumeration) dnsQuery(ctx context.Context, name string, qtype uint16, r *resolve.Resolvers, attempts int) (*dns.Msg, error) {
	msg := resolve.QueryMsg(name, qtype)

	for num := 0; num < attempts; num++ {
		select {
		case <-ctx.Done():
			return nil, errors.New("context expired")
		default:
		}

		resp, err := r.QueryBlocking(ctx, msg)
		if err != nil {
			continue
		}
		if resp.Rcode == dns.RcodeNameError {
			return nil, errors.New("name does not exist")
		}
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
			return nil, errors.New("no record of this type")
		}
		if resp.Rcode == dns.RcodeSuccess {
			return resp, nil
		}
	}
	return nil, nil
}

func (e *Enumeration) wildcardDetected(ctx context.Context, req *requests.DNSRequest, resp *dns.Msg) bool {
	return e.Sys.TrustedResolvers().WildcardDetected(ctx, resp, req.Domain)
}

func convertAnswers(ans []*resolve.ExtractedAnswer) []requests.DNSAnswer {
	var answers []requests.DNSAnswer

	for _, a := range ans {
		answers = append(answers, requests.DNSAnswer{
			Name: a.Name,
			Type: int(a.Type),
			Data: a.Data,
		})
	}
	return answers
}
