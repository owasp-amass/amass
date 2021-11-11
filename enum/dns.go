// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"strings"
	"sync"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/caffix/resolve"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// InitialQueryTypes include the DNS record types that are queried for a discovered name.
var InitialQueryTypes = []uint16{
	dns.TypeCNAME,
	dns.TypeA,
	dns.TypeAAAA,
}

// dNSTask is the task that handles all DNS name resolution requests within the pipeline.
type dNSTask struct {
	enum *Enumeration
}

// newDNSTask returns a dNSTask specific to the provided Enumeration.
func newDNSTask(e *Enumeration) *dNSTask {
	return &dNSTask{enum: e}
}

func (dt *dNSTask) blacklistTaskFunc() pipeline.TaskFunc {
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

func (dt *dNSTask) rootTaskFunc() pipeline.TaskFunc {
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
func (dt *dNSTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	switch v := data.(type) {
	case *requests.DNSRequest:
		return dt.processDNSRequest(ctx, v, tp)
	case *requests.AddrRequest:
		if dt.reverseDNSQuery(ctx, v.Address, tp) || v.InScope {
			return data, nil
		}
		return nil, nil
	}
	return data, nil
}

func (dt *dNSTask) processDNSRequest(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) (pipeline.Data, error) {
	if req == nil || !req.Valid() {
		return nil, nil
	}
loop:
	for _, t := range InitialQueryTypes {
		select {
		case <-ctx.Done():
			break loop
		default:
		}

		msg := resolve.QueryMsg(req.Name, t)
		resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityLow, resolve.PoolRetryPolicy)
		if err == nil && resp != nil && len(resp.Answer) > 0 {
			if !requests.TrustedTag(req.Tag) &&
				dt.enum.Sys.Pool().WildcardType(ctx, resp, req.Domain) != resolve.WildcardTypeNone {
				break
			}

			ans := resolve.ExtractAnswers(resp)
			if len(ans) == 0 {
				continue
			}

			rr := resolve.AnswersByType(ans, t)
			if len(rr) == 0 {
				continue
			}

			req.Records = append(req.Records, convertAnswers(rr)...)
			if t == dns.TypeCNAME {
				break
			}
		} else {
			if err != nil && err.Error() == "All resolvers have been stopped" {
				return nil, err
			}
			dt.handleResolverError(ctx, err)
		}
	}

	if len(req.Records) > 0 {
		return req, nil
	}
	return nil, nil
}

func (dt *dNSTask) handleResolverError(ctx context.Context, e error) {
	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	rerr, ok := e.(*resolve.ResolveError)
	if !ok {
		return
	}
	if rcode := rerr.Rcode; !cfg.Verbose && (rcode == resolve.TimeoutRcode || rcode == dns.RcodeRefused ||
		rcode == resolve.ResolverErrRcode || rcode == dns.RcodeNameError || rcode == dns.RcodeServerFailure) {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: %v", e))
}

func (dt *dNSTask) subdomainQueries(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
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

func (dt *dNSTask) queryNS(ctx context.Context, name, domain string, ch chan []requests.DNSAnswer, tp pipeline.TaskParams) {
	msg := resolve.QueryMsg(name, dns.TypeNS)
	// Obtain the DNS answers for the NS records related to the domain
	resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy)
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

	dt.handleResolverError(ctx, err)
	ch <- nil
}

func (dt *dNSTask) queryMX(ctx context.Context, name string, ch chan []requests.DNSAnswer) {
	msg := resolve.QueryMsg(name, dns.TypeMX)
	// Obtain the DNS answers for the MX records related to the domain
	resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy)
	if err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeMX)

		ch <- convertAnswers(rr)
		return
	}

	dt.handleResolverError(ctx, err)
	ch <- nil
}

func (dt *dNSTask) querySOA(ctx context.Context, name string, ch chan []requests.DNSAnswer) {
	msg := resolve.QueryMsg(name, dns.TypeSOA)
	// Obtain the DNS answers for the SOA records related to the domain
	resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy)
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
		return
	}

	dt.handleResolverError(ctx, err)
}

func (dt *dNSTask) querySPF(ctx context.Context, name string, ch chan []requests.DNSAnswer) {
	msg := resolve.QueryMsg(name, dns.TypeSPF)
	// Obtain the DNS answers for the SPF records related to the domain
	resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy)
	if err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeSPF)

		ch <- convertAnswers(rr)
		return
	}

	dt.handleResolverError(ctx, err)
	ch <- nil
}

func (dt *dNSTask) queryServiceNames(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	var wg sync.WaitGroup

	wg.Add(len(popularSRVRecords))
	for _, name := range popularSRVRecords {
		go dt.querySingleServiceName(ctx, name+"."+req.Name, req.Domain, &wg, tp)
	}

	wg.Wait()
}

func (dt *dNSTask) querySingleServiceName(ctx context.Context, name, domain string, wg *sync.WaitGroup, tp pipeline.TaskParams) {
	defer wg.Done()

	select {
	case <-ctx.Done():
		return
	default:
	}

	msg := resolve.QueryMsg(name, dns.TypeSRV)
	resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityLow, resolve.PoolRetryPolicy)
	if err != nil || len(resp.Answer) == 0 {
		dt.handleResolverError(ctx, err)
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

	if req.Valid() && dt.enum.Sys.Pool().WildcardType(ctx, resp, domain) == resolve.WildcardTypeNone {
		pipeline.SendData(ctx, "filter", req, tp)
	}
}

func (dt *dNSTask) reverseDNSQuery(ctx context.Context, addr string, tp pipeline.TaskParams) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	msg := resolve.ReverseMsg(addr)
	if msg == nil {
		return false
	}

	resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityLow, resolve.PoolRetryPolicy)
	if err != nil {
		return false
	}

	ans := resolve.ExtractAnswers(resp)
	if len(ans) == 0 {
		return false
	}

	rr := resolve.AnswersByType(ans, dns.TypePTR)
	if len(rr) == 0 {
		return false
	}

	answer := strings.ToLower(resolve.RemoveLastDot(rr[0].Data))
	if amassdns.RemoveAsteriskLabel(answer) != answer {
		return false
	}
	// Check that the name discovered is in scope
	d := dt.enum.Config.WhichDomain(answer)
	if d == "" {
		return false
	}
	if re := dt.enum.Config.DomainRegex(d); re == nil || re.FindString(answer) != answer {
		return false
	}

	ptr := resolve.RemoveLastDot(rr[0].Name)
	domain, err := publicsuffix.EffectiveTLDPlusOne(ptr)
	if err != nil {
		return true
	}

	pipeline.SendData(ctx, "filter", &requests.DNSRequest{
		Name:   ptr,
		Domain: domain,
		Records: []requests.DNSAnswer{{
			Name: ptr,
			Type: 12,
			Data: answer,
		}},
		Tag:    requests.DNS,
		Source: "Reverse DNS",
	}, tp)
	return true
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
