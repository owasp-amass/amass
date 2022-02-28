// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/resolve"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

const maxDNSQueryAttempts int = 10

type fwdElement struct {
	Ctx      context.Context
	Req      *requests.DNSRequest
	Msg      *dns.Msg
	Attempts int
	Tp       pipeline.TaskParams
	Trusted  bool
}

type revElement struct {
	Ctx      context.Context
	Req      *requests.AddrRequest
	Msg      *dns.Msg
	Attempts int
	Tp       pipeline.TaskParams
	Trusted  bool
}

// dnsTask is the task that handles all DNS name resolution requests within the pipeline.
type dnsTask struct {
	enum      *Enumeration
	done      chan struct{}
	countLock sync.Mutex
	sentCount int
	fwdLock   sync.Mutex
	fwds      map[string]*fwdElement
	fwdChan   chan *dns.Msg
	revLock   sync.Mutex
	revs      map[string]*revElement
	revChan   chan *dns.Msg
	max       int
}

// newDNSTask returns a dNSTask specific to the provided Enumeration.
func newDNSTask(e *Enumeration) *dnsTask {
	dt := &dnsTask{
		enum:    e,
		done:    make(chan struct{}, 2),
		fwds:    make(map[string]*fwdElement),
		fwdChan: make(chan *dns.Msg, 1000),
		revs:    make(map[string]*revElement),
		revChan: make(chan *dns.Msg, 1000),
		max:     e.Sys.Resolvers().QPS() * 2,
	}

	go dt.processFwdResponses()
	go dt.processRevResponses()
	return dt
}

func (dt *dnsTask) getCount() int {
	dt.countLock.Lock()
	defer dt.countLock.Unlock()
	return dt.sentCount
}

func (dt *dnsTask) incCount() {
	dt.countLock.Lock()
	defer dt.countLock.Unlock()
	dt.sentCount++
}

func (dt *dnsTask) decCount() {
	dt.countLock.Lock()
	defer dt.countLock.Unlock()
	dt.sentCount--
}

func fwdkey(name string, qtype uint16) string {
	n := strings.ToLower(resolve.RemoveLastDot(name))
	return fmt.Sprintf("%s%s", n, strconv.Itoa(int(qtype)))
}

func (dt *dnsTask) addFwdElement(f *fwdElement) bool {
	dt.fwdLock.Lock()
	defer dt.fwdLock.Unlock()

	var success bool
	key := fwdkey(f.Msg.Question[0].Name, f.Msg.Question[0].Qtype)
	if _, found := dt.fwds[key]; !found {
		dt.fwds[key] = f
		success = true
	}
	return success
}

func (dt *dnsTask) getFwdElement(name string, qtype uint16) *fwdElement {
	dt.fwdLock.Lock()
	defer dt.fwdLock.Unlock()

	return dt.fwds[fwdkey(name, qtype)]
}

func (dt *dnsTask) delFwdElement(name string, qtype uint16) {
	dt.fwdLock.Lock()
	defer dt.fwdLock.Unlock()

	key := fwdkey(name, qtype)
	dt.fwds[key] = nil
	delete(dt.fwds, key)
}

func revkey(name string) string {
	return strings.ToLower(resolve.RemoveLastDot(name))
}

func (dt *dnsTask) addRevElement(r *revElement) bool {
	dt.revLock.Lock()
	defer dt.revLock.Unlock()

	var success bool
	key := revkey(r.Msg.Question[0].Name)
	if _, found := dt.revs[key]; !found {
		dt.revs[key] = r
		success = true
	}
	return success
}

func (dt *dnsTask) getRevElement(name string) *revElement {
	dt.revLock.Lock()
	defer dt.revLock.Unlock()

	return dt.revs[revkey(name)]
}

func (dt *dnsTask) delRevElement(name string) {
	dt.revLock.Lock()
	defer dt.revLock.Unlock()

	key := revkey(name)
	dt.revs[key] = nil
	delete(dt.revs, key)
}

func (dt *dnsTask) blacklistTaskFunc() pipeline.TaskFunc {
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		select {
		case <-ctx.Done():
			return nil, nil
		default:
		}

		var name string
		switch v := data.(type) {
		case *requests.DNSRequest:
			if v != nil && v.Valid() {
				name = v.Name
			}
		case *requests.ResolvedRequest:
			if v != nil && v.Valid() {
				name = v.Name
			}
		case *requests.SubdomainRequest:
			if v != nil && v.Valid() {
				name = v.Name
			}
		case *requests.ZoneXFRRequest:
			if v != nil {
				name = v.Name
			}
		default:
			return data, nil
		}

		if name != "" && !dt.enum.Config.Blacklisted(name) {
			return data, nil
		}
		return nil, nil
	})
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
			if v.Domain == "" || v.Name != v.Domain {
				return data, nil
			}
			r = v.Clone().(*requests.DNSRequest)
		case *requests.SubdomainRequest:
			r = &requests.DNSRequest{
				Name:   v.Name,
				Domain: v.Domain,
				Tag:    v.Tag,
				Source: v.Source,
			}
		default:
			return data, nil
		}

		if dt.enum.Config.IsDomainInScope(r.Name) {
			go func() {
				dt.subdomainQueries(ctx, r, tp)
				dt.queryServiceNames(ctx, r, tp)
			}()
		}
		return data, nil
	})
}

// Process implements the pipeline Task interface.
func (dt *dnsTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-dt.done:
		return nil, nil
	default:
	}

	select {
	case <-ctx.Done():
		dt.waitForResponses()
		close(dt.done)
		return nil, nil
	default:
	}

	for dt.getCount() >= dt.max {
		time.Sleep(100 * time.Millisecond)
	}

	switch v := data.(type) {
	case *requests.DNSRequest:
		dt.processFwdRequest(ctx, v, tp)
	case *requests.AddrRequest:
		dt.processRevRequest(ctx, v, tp)
		if v.InScope {
			return data, nil
		}
	}
	return nil, nil
}

func (dt *dnsTask) waitForResponses() {
	for dt.getCount() > 0 {
		time.Sleep(100 * time.Millisecond)
	}
}

func (dt *dnsTask) processFwdRequest(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	if req != nil && req.Valid() {
		dt.sendFwdQuery(ctx, req, dns.TypeCNAME, tp)
	}
}

func (dt *dnsTask) sendFwdQuery(ctx context.Context, req *requests.DNSRequest, qtype uint16, tp pipeline.TaskParams) {
	msg := resolve.QueryMsg(req.Name, qtype)
	f := &fwdElement{
		Ctx:      ctx,
		Req:      req,
		Msg:      msg,
		Attempts: 1,
		Tp:       tp,
	}

	if dt.addFwdElement(f) {
		dt.incCount()
		dt.enum.Sys.Resolvers().Query(ctx, msg, dt.fwdChan)
	}
}

func (dt *dnsTask) processFwdResponses() {
	for {
		select {
		case <-dt.done:
			return
		case msg := <-dt.fwdChan:
			if e := dt.getFwdElement(msg.Question[0].Name, msg.Question[0].Qtype); e != nil && dt.handleFwdElement(e, msg) {
				dt.delFwdElement(msg.Question[0].Name, msg.Question[0].Qtype)
				dt.decCount()
			}
		}
	}
}

func (dt *dnsTask) handleFwdElement(f *fwdElement, resp *dns.Msg) bool {
	select {
	case <-f.Ctx.Done():
		return true
	default:
	}
	// Check if the response indicates that the name does not exist
	if resp.Rcode == dns.RcodeNameError {
		return true
	}

	qtype := resp.Question[0].Qtype
	if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && qtype == dns.TypeCNAME {
		dt.sendFwdQuery(f.Ctx, f.Req, dns.TypeA, f.Tp)
		dt.sendFwdQuery(f.Ctx, f.Req, dns.TypeAAAA, f.Tp)
		return true
	}
	// Was there another reason why the query failed?
	if resp.Rcode != dns.RcodeSuccess {
		// Should the query be sent again?
		if f.Attempts < maxDNSQueryAttempts {
			f.Attempts++
			if f.Trusted {
				dt.enum.Sys.TrustedResolvers().Query(f.Ctx, f.Msg, dt.fwdChan)
			} else {
				dt.enum.Sys.Resolvers().Query(f.Ctx, f.Msg, dt.fwdChan)
			}
			return false
		}
		return true
	}

	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		return true
	}

	rr := resolve.AnswersByType(ans, qtype)
	if len(rr) == 0 {
		return true
	}

	if !f.Trusted {
		f.Trusted = true
		f.Attempts = 1
		dt.enum.Sys.TrustedResolvers().Query(f.Ctx, f.Msg, dt.fwdChan)
		return false
	}

	f.Req.Records = append(f.Req.Records, convertAnswers(rr)...)
	if len(f.Req.Records) > 0 {
		go dt.wildcardFiltering(f.Ctx, f.Req, resp, f.Tp)
	}
	return true
}

func (dt *dnsTask) wildcardFiltering(ctx context.Context, req *requests.DNSRequest, resp *dns.Msg, tp pipeline.TaskParams) {
	if !requests.TrustedTag(req.Tag) &&
		dt.enum.Sys.TrustedResolvers().WildcardType(ctx, resp, req.Domain) != resolve.WildcardTypeNone {
		return
	}
	pipeline.SendData(ctx, "filter", req, tp)
}

func (dt *dnsTask) processRevRequest(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	if req != nil {
		dt.sendRevQuery(ctx, req, tp)
	}
}

func (dt *dnsTask) sendRevQuery(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	msg := resolve.ReverseMsg(req.Address)
	if msg == nil {
		return
	}

	r := &revElement{
		Ctx:      ctx,
		Req:      req,
		Msg:      msg,
		Attempts: 1,
		Tp:       tp,
	}

	if dt.addRevElement(r) {
		dt.incCount()
		dt.enum.Sys.Resolvers().Query(ctx, msg, dt.revChan)
	}
}

func (dt *dnsTask) processRevResponses() {
	for {
		select {
		case <-dt.done:
			return
		case msg := <-dt.revChan:
			if e := dt.getRevElement(msg.Question[0].Name); e != nil && dt.handleRevElement(e, msg) {
				dt.delRevElement(msg.Question[0].Name)
				dt.decCount()
			}
		}
	}
}

func (dt *dnsTask) handleRevElement(r *revElement, resp *dns.Msg) bool {
	select {
	case <-r.Ctx.Done():
		return true
	default:
	}
	// Check if the response indicates that the name does not exist
	if resp.Rcode == dns.RcodeNameError {
		return true
	}
	// Was there another reason why the query failed?
	if resp.Rcode != dns.RcodeSuccess {
		// Should the query be sent again?
		if r.Attempts < maxDNSQueryAttempts {
			r.Attempts++
			if r.Trusted {
				dt.enum.Sys.TrustedResolvers().Query(r.Ctx, r.Msg, dt.revChan)
			} else {
				dt.enum.Sys.Resolvers().Query(r.Ctx, r.Msg, dt.revChan)
			}
			return false
		}
		return true
	}

	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		return true
	}

	rr := resolve.AnswersByType(ans, dns.TypePTR)
	if len(rr) == 0 {
		return true
	}

	if !r.Trusted {
		r.Trusted = true
		r.Attempts = 1
		dt.enum.Sys.TrustedResolvers().Query(r.Ctx, r.Msg, dt.revChan)
		return false
	}

	answer := strings.ToLower(resolve.RemoveLastDot(rr[0].Data))
	if amassdns.RemoveAsteriskLabel(answer) != answer {
		return true
	}
	// Check that the name discovered is in scope
	d := dt.enum.Config.WhichDomain(answer)
	if d == "" {
		return true
	}
	if re := dt.enum.Config.DomainRegex(d); re == nil || re.FindString(answer) != answer {
		return true
	}

	ptr := strings.ToLower(resolve.RemoveLastDot(rr[0].Name))
	domain, err := publicsuffix.EffectiveTLDPlusOne(ptr)
	if err != nil {
		return true
	}

	pipeline.SendData(r.Ctx, "filter", &requests.DNSRequest{
		Name:   ptr,
		Domain: domain,
		Records: []requests.DNSAnswer{{
			Name: ptr,
			Type: int(dns.TypePTR),
			Data: answer,
		}},
		Tag:    requests.DNS,
		Source: "Reverse DNS",
	}, r.Tp)
	return true
}

func (dt *dnsTask) subdomainQueries(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	ch := make(chan []requests.DNSAnswer, 4)

	go dt.queryNS(ctx, req.Name, req.Domain, ch, tp)
	go dt.queryMX(ctx, req.Name, ch)
	go dt.querySOA(ctx, req.Name, ch)
	go dt.querySPF(ctx, req.Name, ch)

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
	resp, err := dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, resolve.QueryMsg(name, dns.TypeNS))
	if err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeNS)

		var records []requests.DNSAnswer
		for _, a := range rr {
			pipeline.SendData(ctx, "active", &requests.ZoneXFRRequest{
				Name:   name,
				Domain: domain,
				Server: a.Data,
				Tag:    requests.DNS,
				Source: "DNS",
			}, tp)
			records = append(records, convertAnswers([]*resolve.ExtractedAnswer{a})...)
		}
		ch <- records
		return
	}
	ch <- nil
}

func (dt *dnsTask) queryMX(ctx context.Context, name string, ch chan []requests.DNSAnswer) {
	// Obtain the DNS answers for the MX records related to the domain
	resp, err := dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, resolve.QueryMsg(name, dns.TypeMX))
	if err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeMX)
		ch <- convertAnswers(rr)
		return
	}
	ch <- nil
}

func (dt *dnsTask) querySOA(ctx context.Context, name string, ch chan []requests.DNSAnswer) {
	// Obtain the DNS answers for the SOA records related to the domain
	resp, err := dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, resolve.QueryMsg(name, dns.TypeSOA))
	if err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeSOA)

		var records []requests.DNSAnswer
		for _, a := range rr {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]
			records = append(records, convertAnswers([]*resolve.ExtractedAnswer{a})...)
		}
		ch <- records
	}
}

func (dt *dnsTask) querySPF(ctx context.Context, name string, ch chan []requests.DNSAnswer) {
	// Obtain the DNS answers for the SPF records related to the domain
	resp, err := dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, resolve.QueryMsg(name, dns.TypeSPF))
	if err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeSPF)
		ch <- convertAnswers(rr)
		return
	}
	ch <- nil
}

func (dt *dnsTask) queryServiceNames(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	var wg sync.WaitGroup

	wg.Add(len(popularSRVRecords))
	for _, name := range popularSRVRecords {
		go dt.querySingleServiceName(ctx, name+"."+req.Name, req.Domain, &wg, tp)
	}
	wg.Wait()
}

func (dt *dnsTask) querySingleServiceName(ctx context.Context, name, domain string, wg *sync.WaitGroup, tp pipeline.TaskParams) {
	defer wg.Done()

	select {
	case <-ctx.Done():
		return
	default:
	}

	resp, err := dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, resolve.QueryMsg(name, dns.TypeSRV))
	if err != nil || len(resp.Answer) == 0 {
		return
	}

	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		return
	}

	rr := resolve.AnswersByType(ans, dns.TypeSRV)
	if len(rr) == 0 {
		return
	}

	req := &requests.DNSRequest{
		Name:    name,
		Domain:  domain,
		Records: convertAnswers(rr),
		Tag:     requests.DNS,
		Source:  "DNS",
	}

	if req.Valid() && dt.enum.Sys.TrustedResolvers().WildcardType(ctx, resp, domain) == resolve.WildcardTypeNone {
		pipeline.SendData(ctx, "filter", req, tp)
	}
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
