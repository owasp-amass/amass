// Copyright © by Jeff Foley 2017-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"strings"
	"sync"

	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/resolve"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

const maxDNSQueryAttempts int = 10

// InitialQueryTypes include the DNS record types that are queried for a discovered name.
var InitialQueryTypes = []uint16{
	dns.TypeCNAME,
	dns.TypeA,
	dns.TypeAAAA,
}

// dnsTask is the task that handles all DNS name resolution requests within the pipeline.
type dnsTask struct {
	enum *Enumeration
	done chan struct{}
}

// newDNSTask returns a dNSTask specific to the provided Enumeration.
func newDNSTask(e *Enumeration) *dnsTask {
	return &dnsTask{
		enum: e,
		done: make(chan struct{}, 2),
	}
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

	switch v := data.(type) {
	case *requests.DNSRequest:
		return dt.processFwdRequest(ctx, v, tp)
	case *requests.AddrRequest:
		if dt.processRevRequest(ctx, v.Address, tp) || v.InScope {
			return data, nil
		}
		return nil, nil
	}
	return data, nil
}

func (dt *dnsTask) processFwdRequest(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) (pipeline.Data, error) {
	if req == nil || !req.Valid() {
		return nil, nil
	}

	var err error
	var resp *dns.Msg
loop:
	for _, qtype := range InitialQueryTypes {
		select {
		case <-dt.done:
			break loop
		case <-ctx.Done():
			break loop
		default:
		}

		msg := resolve.QueryMsg(req.Name, qtype)
		resp, err = dt.enum.Sys.Resolvers().QueryBlocking(ctx, msg)
		// Check if the response indicates that the name does not exist
		if err != nil || resp.Rcode == dns.RcodeNameError {
			return nil, nil
		}
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && qtype == dns.TypeCNAME {
			continue
		}

		// Was there another reason why the query failed?
		for attempts := 1; attempts < maxDNSQueryAttempts && resp.Rcode != dns.RcodeSuccess; attempts++ {
			resp, err = dt.enum.Sys.Resolvers().QueryBlocking(ctx, msg)
			if err != nil {
				break loop
			}
		}
		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		resp, err = dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, msg)
		// Check if the response indicates that the name does not exist
		if err != nil || resp.Rcode == dns.RcodeNameError {
			return nil, nil
		}
		if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && qtype == dns.TypeCNAME {
			continue
		}
		for attempts := 1; attempts < maxDNSQueryAttempts && resp.Rcode != dns.RcodeSuccess; attempts++ {
			resp, err = dt.enum.Sys.Resolvers().QueryBlocking(ctx, msg)
			// Check if the response indicates that the name does not exist
			if err != nil || resp.Rcode == dns.RcodeNameError {
				return nil, nil
			}
			if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 && qtype == dns.TypeCNAME {
				continue loop
			}
		}
		if resp.Rcode != dns.RcodeSuccess {
			continue
		}

		ans := resolve.ExtractAnswers(resp)
		if len(ans) == 0 {
			continue
		}

		rr := resolve.AnswersByType(ans, qtype)
		if len(rr) == 0 {
			continue
		}

		req.Records = append(req.Records, convertAnswers(rr)...)
	}

	if len(req.Records) > 0 && dt.wildcardFiltering(ctx, req, resp) {
		return req, nil
	}
	return nil, nil
}

func (dt *dnsTask) wildcardFiltering(ctx context.Context, req *requests.DNSRequest, resp *dns.Msg) bool {
	if !requests.TrustedTag(req.Tag) && dt.enum.Sys.TrustedResolvers().WildcardDetected(ctx, resp, req.Domain) {
		return false
	}
	return true
}

func (dt *dnsTask) processRevRequest(ctx context.Context, addr string, tp pipeline.TaskParams) bool {
	select {
	case <-ctx.Done():
		return false
	default:
	}

	msg := resolve.ReverseMsg(addr)
	if msg == nil {
		return false
	}

	resp, err := dt.enum.Sys.Resolvers().QueryBlocking(ctx, msg)
	if err != nil || resp.Rcode == dns.RcodeNameError {
		return false
	}
	// Was there another reason why the query failed?
	for attempts := 1; attempts < maxDNSQueryAttempts && resp.Rcode != dns.RcodeSuccess; attempts++ {
		resp, err = dt.enum.Sys.Resolvers().QueryBlocking(ctx, msg)
		if err != nil {
			return false
		}
	}
	if resp.Rcode != dns.RcodeSuccess {
		return false
	}

	resp, err = dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, msg)
	if err != nil || resp.Rcode == dns.RcodeNameError {
		return false
	}
	// Was there another reason why the query failed?
	for attempts := 1; attempts < maxDNSQueryAttempts && resp.Rcode != dns.RcodeSuccess; attempts++ {
		resp, err = dt.enum.Sys.TrustedResolvers().QueryBlocking(ctx, msg)
		if err != nil {
			return false
		}
	}
	if resp.Rcode != dns.RcodeSuccess {
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

	ptr := strings.ToLower(resolve.RemoveLastDot(rr[0].Name))
	domain, err := publicsuffix.EffectiveTLDPlusOne(ptr)
	if err != nil {
		return true
	}

	pipeline.SendData(ctx, "filter", &requests.DNSRequest{
		Name:   ptr,
		Domain: domain,
		Records: []requests.DNSAnswer{{
			Name: ptr,
			Type: int(dns.TypePTR),
			Data: answer,
		}},
		Tag:    requests.DNS,
		Source: "Reverse DNS",
	}, tp)
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

	if req.Valid() && !dt.enum.Sys.TrustedResolvers().WildcardDetected(ctx, resp, domain) {
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
