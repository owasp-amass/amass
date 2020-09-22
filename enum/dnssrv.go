// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/v3/datasrcs"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/miekg/dns"
)

// InitialQueryTypes include the DNS record types that are
// initially requested for a discovered name
var InitialQueryTypes = []string{
	"CNAME",
	"TXT",
	"A",
	"AAAA",
}

// DNSService is the Service that handles all DNS name resolution requests within
// the architecture.
type DNSService struct {
	requests.BaseService

	SourceType string
	sys        systems.System
}

// NewDNSService returns he object initialized, but not yet started.
func NewDNSService(sys systems.System) *DNSService {
	ds := &DNSService{
		SourceType: requests.DNS,
		sys:        sys,
	}

	ds.BaseService = *requests.NewBaseService(ds, "DNS Service")
	return ds
}

// Type implements the Service interface.
func (ds *DNSService) Type() string {
	return ds.SourceType
}

// OnDNSRequest implements the Service interface.
func (ds *DNSService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	num := len(InitialQueryTypes)

	for i := 0; i < num; i++ {
		ds.sys.PerformDNSQuery()
	}

	go ds.processDNSRequest(ctx, req)
}

func (ds *DNSService) processDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if cfg.Blacklisted(req.Name) {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())

	// Is this a root domain name?
	if req.Name == req.Domain {
		ds.subdomainQueries(ctx, req)
		ds.queryServiceNames(ctx, req)
	}

	req.Records = ds.queryInitialTypes(ctx, req)
	if len(req.Records) > 0 {
		ds.resolvedName(ctx, req)
	}
}

func (ds *DNSService) queryInitialTypes(ctx context.Context, req *requests.DNSRequest) []requests.DNSAnswer {
	var answers []requests.DNSAnswer

	_, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return answers
	}

	for _, t := range InitialQueryTypes {
		bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())

		if a, err := ds.sys.Pool().Resolve(ctx, req.Name, t, resolvers.PriorityLow, func(times int, priority int, msg *dns.Msg) bool {
			var retry bool

			if resolvers.PoolRetryPolicy(times, priority, msg) {
				ds.sys.PerformDNSQuery()
				retry = true
			}
			return retry
		}); err == nil {
			answers = append(answers, a...)
		} else {
			ds.handleResolverError(ctx, err)
		}
	}

	return answers
}

func (ds *DNSService) handleResolverError(ctx context.Context, e error) {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	rerr, ok := e.(*resolvers.ResolveError)
	if !ok {
		return
	}

	if rcode := rerr.Rcode; cfg.Verbose || rcode == resolvers.NotAvailableRcode ||
		rcode == resolvers.TimeoutRcode || rcode == resolvers.ResolverErrRcode ||
		rcode == dns.RcodeRefused || rcode == dns.RcodeServerFailure || rcode == dns.RcodeNotImplemented {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: %v", e))
	}
}

func (ds *DNSService) resolvedName(ctx context.Context, req *requests.DNSRequest) {
	_, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if !requests.TrustedTag(req.Tag) && ds.sys.Pool().MatchesWildcard(ctx, req) {
		return
	}

	bus.Publish(requests.NameResolvedTopic, eventbus.PriorityHigh, req)
}

// OnSubdomainDiscovered implements the Service interface.
func (ds *DNSService) OnSubdomainDiscovered(ctx context.Context, req *requests.DNSRequest, times int) {
	if req != nil && times == 1 {
		go ds.processSubdomain(ctx, req)
	}
}

func (ds *DNSService) processSubdomain(ctx context.Context, req *requests.DNSRequest) {
	cfg, _, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if cfg.Blacklisted(req.Name) {
		return
	}

	ds.subdomainQueries(ctx, req)
	ds.queryServiceNames(ctx, req)
}

func (ds *DNSService) subdomainQueries(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	answers := ds.queryInitialTypes(ctx, req)
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())
	// Obtain the DNS answers for the NS records related to the domain
	if ans, err := ds.sys.Pool().Resolve(ctx, req.Name, "NS", resolvers.PriorityHigh, resolvers.PoolRetryPolicy); err == nil {
		for _, a := range ans {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]

			if cfg.Active {
				go ds.attemptZoneWalk(ctx, req.Name, a.Data)
				go ds.attemptZoneXFR(ctx, req.Name, req.Domain, a.Data)
			} else {
				go ds.attemptZoneWalk(ctx, req.Name, "")
			}
			answers = append(answers, a)
		}
	} else {
		ds.handleResolverError(ctx, err)
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())
	// Obtain the DNS answers for the MX records related to the domain
	if ans, err := ds.sys.Pool().Resolve(ctx, req.Name, "MX", resolvers.PriorityHigh, resolvers.PoolRetryPolicy); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.handleResolverError(ctx, err)
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())
	// Obtain the DNS answers for the SOA records related to the domain
	if ans, err := ds.sys.Pool().Resolve(ctx, req.Name, "SOA", resolvers.PriorityHigh, resolvers.PoolRetryPolicy); err == nil {
		for _, a := range ans {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]

			answers = append(answers, a)
		}
	} else {
		ds.handleResolverError(ctx, err)
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())
	// Obtain the DNS answers for the SPF records related to the domain
	if ans, err := ds.sys.Pool().Resolve(ctx, req.Name, "SPF", resolvers.PriorityHigh, resolvers.PoolRetryPolicy); err == nil {
		answers = append(answers, ans...)
	} else {
		ds.handleResolverError(ctx, err)
	}

	if len(answers) > 0 {
		bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())

		ds.resolvedName(ctx, &requests.DNSRequest{
			Name:    req.Name,
			Domain:  req.Domain,
			Records: answers,
			Tag:     requests.DNS,
			Source:  "DNS",
		})
	}
}

func (ds *DNSService) attemptZoneXFR(ctx context.Context, sub, domain, server string) {
	_, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	addr, err := ds.nameserverAddr(ctx, server)
	if addr == "" {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("DNS: Zone XFR failed: %v", err))
		return
	}

	reqs, err := resolvers.ZoneTransfer(sub, domain, addr)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("DNS: Zone XFR failed: %s: %v", server, err))
		return
	}

	for _, req := range reqs {
		ds.resolvedName(ctx, req)
	}
}

func (ds *DNSService) attemptZoneWalk(ctx context.Context, domain, server string) {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	var r resolvers.Resolver
	if server != "" {
		r = resolvers.NewBaseResolver(server)
		if r == nil {
			return
		}
		defer r.Stop()
	} else {
		r = ds.sys.Pool()
	}

	names, _, err := r.NsecTraversal(ctx, domain, resolvers.PriorityHigh)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("DNS: Zone Walk failed: %s: %v", domain, err))
		return
	}

	for _, name := range names {
		if domain := cfg.WhichDomain(name); domain != "" {
			bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    requests.DNS,
				Source: "NSEC Walk",
			})
		}
	}
}

func (ds *DNSService) nameserverAddr(ctx context.Context, server string) (string, error) {
	a, err := ds.sys.Pool().Resolve(ctx, server, "A", resolvers.PriorityHigh, resolvers.RetryPolicy)
	if err != nil {
		a, err = ds.sys.Pool().Resolve(ctx, server, "AAAA", resolvers.PriorityHigh, resolvers.RetryPolicy)
		if err != nil {
			return "", fmt.Errorf("DNS server has no A or AAAA record: %s: %v", server, err)
		}
	}
	return a[0].Data, nil
}

func (ds *DNSService) queryServiceNames(ctx context.Context, req *requests.DNSRequest) {
	_, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	for _, name := range popularSRVRecords {
		srvName := name + "." + req.Name

		bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, ds.String())

		if a, err := ds.sys.Pool().Resolve(ctx, srvName, "SRV", resolvers.PriorityHigh, resolvers.PoolRetryPolicy); err == nil {
			ds.resolvedName(ctx, &requests.DNSRequest{
				Name:    srvName,
				Domain:  req.Domain,
				Records: a,
				Tag:     requests.DNS,
				Source:  "DNS",
			})
		} else {
			ds.handleResolverError(ctx, err)
		}
	}
}
