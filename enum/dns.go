// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"strings"

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

func (dt *dNSTask) makeBlacklistTaskFunc() pipeline.TaskFunc {
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

func (dt *dNSTask) makeRootTaskFunc() pipeline.TaskFunc {
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
			if v.Name != v.Domain {
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

		tp.NewData() <- r
		defer func() { tp.ProcessedData() <- r }()

		dt.subdomainQueries(ctx, r, tp)
		dt.queryServiceNames(ctx, r, tp)
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

		var nxdomain bool
		msg := resolve.QueryMsg(req.Name, t)
		resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityLow, func(times, priority int, m *dns.Msg) bool {
			// Try one more time if we receive NXDOMAIN
			if m.Rcode == dns.RcodeNameError && !nxdomain {
				nxdomain = true
				return true
			}
			return resolve.PoolRetryPolicy(times, priority, m)
		})

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

	if rcode := rerr.Rcode; !cfg.Verbose && (rcode == resolve.TimeoutRcode ||
		rcode == resolve.ResolverErrRcode || rcode == dns.RcodeNameError || rcode == dns.RcodeServerFailure) {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: %v", e))
}

func (dt *dNSTask) subdomainQueries(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	msg := resolve.QueryMsg(req.Name, dns.TypeNS)
	// Obtain the DNS answers for the NS records related to the domain
	if resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy); err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeNS)

		for _, a := range rr {
			go pipeline.SendData(ctx, "active", &requests.ZoneXFRRequest{
				Name:   req.Name,
				Domain: req.Domain,
				Server: a.Data,
				Tag:    requests.DNS,
				Source: "DNS",
			}, tp)

			req.Records = append(req.Records, convertAnswers([]*resolve.ExtractedAnswer{a})...)
		}
	} else {
		dt.handleResolverError(ctx, err)
	}

	msg = resolve.QueryMsg(req.Name, dns.TypeMX)
	// Obtain the DNS answers for the MX records related to the domain
	if resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy); err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeMX)

		req.Records = append(req.Records, convertAnswers(rr)...)
	} else {
		dt.handleResolverError(ctx, err)
	}

	msg = resolve.QueryMsg(req.Name, dns.TypeSOA)
	// Obtain the DNS answers for the SOA records related to the domain
	if resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy); err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeSOA)

		for _, a := range rr {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]

			req.Records = append(req.Records, convertAnswers([]*resolve.ExtractedAnswer{a})...)
		}
	} else {
		dt.handleResolverError(ctx, err)
	}

	msg = resolve.QueryMsg(req.Name, dns.TypeSPF)
	// Obtain the DNS answers for the SPF records related to the domain
	if resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityHigh, resolve.PoolRetryPolicy); err == nil {
		ans := resolve.ExtractAnswers(resp)
		rr := resolve.AnswersByType(ans, dns.TypeSPF)

		req.Records = append(req.Records, convertAnswers(rr)...)
	} else {
		dt.handleResolverError(ctx, err)
	}

	if req.Valid() && len(req.Records) > 0 {
		go pipeline.SendData(ctx, "store", req, tp)
	}
}

func (dt *dNSTask) queryServiceNames(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) {
	for _, name := range popularSRVRecords {
		srvName := name + "." + req.Name

		msg := resolve.QueryMsg(srvName, dns.TypeSRV)
		if resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityLow,
			resolve.PoolRetryPolicy); err == nil && len(resp.Answer) > 0 {
			ans := resolve.ExtractAnswers(resp)
			if len(ans) == 0 {
				continue
			}

			rr := resolve.AnswersByType(ans, dns.TypeSRV)
			if len(rr) == 0 {
				continue
			}

			req := &requests.DNSRequest{
				Name:    srvName,
				Domain:  req.Domain,
				Records: convertAnswers(rr),
				Tag:     requests.DNS,
				Source:  "DNS",
			}
			if !req.Valid() {
				continue
			}

			if dt.enum.Sys.Pool().WildcardType(ctx, resp, req.Domain) == resolve.WildcardTypeNone {
				go pipeline.SendData(ctx, "filter", req, tp)
			}
		} else {
			dt.handleResolverError(ctx, err)
		}
	}
}

func (dt *dNSTask) reverseDNSQuery(ctx context.Context, addr string, tp pipeline.TaskParams) bool {
	msg := resolve.ReverseMsg(addr)
	if msg == nil {
		return false
	}

	var nxdomain bool
	resp, err := dt.enum.Sys.Pool().Query(ctx, msg, resolve.PriorityLow, func(times, priority int, m *dns.Msg) bool {
		// Try one more time if we receive NXDOMAIN
		if m.Rcode == dns.RcodeNameError && !nxdomain {
			nxdomain = true
			return true
		}
		return resolve.PoolRetryPolicy(times, priority, m)
	})
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
	if _, ok := dns.IsDomainName(answer); !ok {
		return false
	}

	// Check that the name discovered is in scope
	if dt.enum.Config.WhichDomain(answer) == "" {
		return false
	}

	ptr := resolve.RemoveLastDot(rr[0].Name)
	domain, err := publicsuffix.EffectiveTLDPlusOne(ptr)
	if err != nil {
		return true
	}

	go pipeline.SendData(ctx, "filter", &requests.DNSRequest{
		Name:   ptr,
		Domain: domain,
		Records: []requests.DNSAnswer{{
			Name: ptr,
			Type: 12,
			TTL:  0,
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
