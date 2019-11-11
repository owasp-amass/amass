// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
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
	BaseService

	SourceType string
}

// NewDNSService returns he object initialized, but not yet started.
func NewDNSService(sys System) *DNSService {
	ds := &DNSService{SourceType: requests.DNS}

	ds.BaseService = *NewBaseService(ds, "DNS Service", sys)
	return ds
}

// Type implements the Service interface.
func (ds *DNSService) Type() string {
	return ds.SourceType
}

// OnDNSRequest implements the Service interface.
func (ds *DNSService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	ds.System().Config().SemMaxDNSQueries.Acquire(1)
	go ds.processDNSRequest(ctx, req)
}

func (ds *DNSService) processDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	defer ds.System().Config().SemMaxDNSQueries.Release(1)

	if req == nil || req.Name == "" || req.Domain == "" {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, ds.String())

	if cfg.Blacklisted(req.Name) || (!requests.TrustedTag(req.Tag) &&
		ds.System().Pool().GetWildcardType(ctx, req) == resolvers.WildcardTypeDynamic) {
		return
	}

	bus.Publish(requests.SetActiveTopic, ds.String())

	var answers []requests.DNSAnswer
	for _, t := range InitialQueryTypes {
		if a, _, err := ds.System().Pool().Resolve(ctx, req.Name, t, resolvers.PriorityLow); err == nil {
			answers = append(answers, a...)
		} else {
			bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: %v", err))
		}

		bus.Publish(requests.SetActiveTopic, ds.String())
	}

	req.Records = answers
	if len(req.Records) == 0 {
		// Check if this unresolved name should be output by the enumeration
		if cfg.IncludeUnresolvable && cfg.IsDomainInScope(req.Name) {
			bus.Publish(requests.OutputTopic, &requests.Output{
				Name:   req.Name,
				Domain: req.Domain,
				Tag:    req.Tag,
				Source: req.Source,
			})
		}
		return
	}

	ds.resolvedName(ctx, req)
}

func (ds *DNSService) resolvedName(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	if !requests.TrustedTag(req.Tag) && ds.System().Pool().MatchesWildcard(ctx, req) {
		return
	}

	bus.Publish(requests.NameResolvedTopic, req)
}

// OnSubdomainDiscovered implements the Service interface.
func (ds *DNSService) OnSubdomainDiscovered(ctx context.Context, req *requests.DNSRequest, times int) {
	if req != nil && times == 1 {
		go ds.processSubdomain(ctx, req)
	}
}

func (ds *DNSService) processSubdomain(ctx context.Context, req *requests.DNSRequest) {
	ds.basicQueries(ctx, req.Name, req.Domain)
	ds.queryServiceNames(ctx, req.Name, req.Domain)
}

func (ds *DNSService) basicQueries(ctx context.Context, subdomain, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, ds.String())

	var answers []requests.DNSAnswer
	// Obtain the DNS answers for the NS records related to the domain
	if ans, _, err := ds.System().Pool().Resolve(ctx, subdomain, "NS", resolvers.PriorityCritical); err == nil {
		for _, a := range ans {
			pieces := strings.Split(a.Data, ",")
			a.Data = pieces[len(pieces)-1]

			if cfg.Active {
				go ds.attemptZoneXFR(ctx, subdomain, domain, a.Data)
				//go ds.attemptZoneWalk(domain, a.Data)
			}
			answers = append(answers, a)
		}
	} else {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: NS record query error: %s: %v", subdomain, err))
	}

	bus.Publish(requests.SetActiveTopic, ds.String())

	// Obtain the DNS answers for the MX records related to the domain
	if ans, _, err := ds.System().Pool().Resolve(ctx, subdomain, "MX", resolvers.PriorityCritical); err == nil {
		for _, a := range ans {
			answers = append(answers, a)
		}
	} else {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: MX record query error: %s: %v", subdomain, err))
	}

	bus.Publish(requests.SetActiveTopic, ds.String())

	// Obtain the DNS answers for the SOA records related to the domain
	if ans, _, err := ds.System().Pool().Resolve(ctx, subdomain, "SOA", resolvers.PriorityHigh); err == nil {
		answers = append(answers, ans...)
	} else {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: SOA record query error: %s: %v", subdomain, err))
	}

	bus.Publish(requests.SetActiveTopic, ds.String())

	// Obtain the DNS answers for the SPF records related to the domain
	if ans, _, err := ds.System().Pool().Resolve(ctx, subdomain, "SPF", resolvers.PriorityHigh); err == nil {
		answers = append(answers, ans...)
	} else {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: SPF record query error: %s: %v", subdomain, err))
	}

	if len(answers) > 0 {
		bus.Publish(requests.SetActiveTopic, ds.String())
		ds.resolvedName(ctx, &requests.DNSRequest{
			Name:    subdomain,
			Domain:  domain,
			Records: answers,
			Tag:     requests.DNS,
			Source:  "DNS",
		})
	}
}

func (ds *DNSService) attemptZoneXFR(ctx context.Context, sub, domain, server string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	addr, err := ds.nameserverAddr(ctx, server)
	if addr == "" {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone XFR failed: %v", err))
		return
	}

	reqs, err := resolvers.ZoneTransfer(sub, domain, addr)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone XFR failed: %s: %v", server, err))
		return
	}

	for _, req := range reqs {
		ds.resolvedName(ctx, req)
	}
}

func (ds *DNSService) attemptZoneWalk(ctx context.Context, domain, server string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	addr, err := ds.nameserverAddr(ctx, server)
	if addr == "" {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone Walk failed: %v", err))
		return
	}

	reqs, err := resolvers.NsecTraversal(domain, addr)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("DNS: Zone Walk failed: %s: %v", server, err))
		return
	}

	for _, req := range reqs {
		ds.DNSRequest(ctx, req)
	}
}

func (ds *DNSService) nameserverAddr(ctx context.Context, server string) (string, error) {
	a, _, err := ds.System().Pool().Resolve(ctx, server, "A", resolvers.PriorityHigh)
	if err != nil {
		a, _, err = ds.System().Pool().Resolve(ctx, server, "AAAA", resolvers.PriorityHigh)
		if err != nil {
			return "", fmt.Errorf("DNS server has no A or AAAA record: %s: %v", server, err)
		}
	}
	return a[0].Data, nil
}

func (ds *DNSService) queryServiceNames(ctx context.Context, subdomain, domain string) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, ds.String())

	for _, name := range popularSRVRecords {
		srvName := name + "." + subdomain

		if a, _, err := ds.System().Pool().Resolve(ctx, srvName, "SRV", resolvers.PriorityHigh); err == nil {
			ds.resolvedName(ctx, &requests.DNSRequest{
				Name:    srvName,
				Domain:  domain,
				Records: a,
				Tag:     requests.DNS,
				Source:  "DNS",
			})
		}

		bus.Publish(requests.SetActiveTopic, ds.String())
	}
}
