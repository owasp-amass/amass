// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// DataManagerService is the Service that handles all data collected
// within the architecture. This is achieved by watching all the RESOLVED events.
type DataManagerService struct {
	requests.BaseService

	sys   systems.System
	graph *graph.Graph
}

// NewDataManagerService returns he object initialized, but not yet started.
func NewDataManagerService(sys systems.System, g *graph.Graph) *DataManagerService {
	dms := &DataManagerService{
		sys:   sys,
		graph: g,
	}

	dms.BaseService = *requests.NewBaseService(dms, "Data Manager")
	return dms
}

// OnDNSRequest implements the Service interface.
func (dms *DataManagerService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	// Check for CNAME records first
	for i, r := range req.Records {
		req.Records[i].Name = strings.Trim(strings.ToLower(r.Name), ".")
		req.Records[i].Data = strings.Trim(strings.ToLower(r.Data), ".")

		if uint16(r.Type) == dns.TypeCNAME {
			dms.insertCNAME(ctx, req, i)
			// Do not enter more than the CNAME record
			return
		}
	}

	for i, r := range req.Records {
		bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

		switch uint16(r.Type) {
		case dns.TypeA:
			dms.insertA(ctx, req, i)
		case dns.TypeAAAA:
			dms.insertAAAA(ctx, req, i)
		case dns.TypePTR:
			dms.insertPTR(ctx, req, i)
		case dns.TypeSRV:
			dms.insertSRV(ctx, req, i)
		case dns.TypeNS:
			dms.insertNS(ctx, req, i)
		case dns.TypeMX:
			dms.insertMX(ctx, req, i)
		case dns.TypeTXT:
			dms.insertTXT(ctx, req, i)
		case dns.TypeSOA:
			dms.insertSOA(ctx, req, i)
		case dns.TypeSPF:
			dms.insertSPF(ctx, req, i)
		}
	}
}

// OnASNRequest implements the Service interface.
func (dms *DataManagerService) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	if req.Address == "" || req.Prefix == "" || req.Description == "" {
		return
	}

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	err := dms.graph.InsertInfrastructure(req.ASN, req.Description,
		req.Address, req.Prefix, req.Source, req.Tag, cfg.UUID.String())
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s failed to insert infrastructure data: %v", dms.String(), dms.graph, err),
		)
	}
}

func (dms *DataManagerService) insertCNAME(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		return
	}

	domain = strings.ToLower(domain)
	if domain == "" {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	if err := dms.graph.InsertCNAME(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s failed to insert CNAME: %v", dms.graph, err))
	}

	// Important - Allows chained CNAME records to be resolved until an A/AAAA record
	bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "DNS",
	})
}

func (dms *DataManagerService) insertA(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	if err := dms.graph.InsertA(req.Name, addr, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s failed to insert A record: %v", dms.graph, err))
	}

	bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
		Address: addr,
		Domain:  req.Domain,
		Tag:     req.Tag,
		Source:  req.Source,
	})
}

func (dms *DataManagerService) insertAAAA(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	if err := dms.graph.InsertAAAA(req.Name, addr, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s failed to insert AAAA record: %v", dms.graph, err))
	}

	bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
		Address: addr,
		Domain:  req.Domain,
		Tag:     req.Tag,
		Source:  req.Source,
	})
}

func (dms *DataManagerService) insertPTR(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}

	// Do not go further if the target is not in scope
	domain := strings.ToLower(cfg.WhichDomain(target))
	if domain == "" {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	if err := dms.graph.InsertPTR(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s failed to insert PTR record: %v", dms.graph, err))
	}

	bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: req.Source,
	})
}

func (dms *DataManagerService) insertSRV(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	service := resolvers.RemoveLastDot(req.Records[recidx].Name)
	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" || service == "" {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	if err := dms.graph.InsertSRV(req.Name, service, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s failed to insert SRV record: %v", dms.graph, err))
	}

	if domain := cfg.WhichDomain(target); domain != "" {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    req.Tag,
			Source: req.Source,
		})
	}
}

func (dms *DataManagerService) insertNS(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	pieces := strings.Split(req.Records[recidx].Data, ",")
	target := pieces[len(pieces)-1]
	if target == "" {
		return
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		return
	}

	domain = strings.ToLower(domain)
	if domain == "" {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	if err := dms.graph.InsertNS(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s failed to insert NS record: %v", dms.graph, err))
	}

	if target != domain {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}
}

func (dms *DataManagerService) insertMX(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		return
	}

	domain = strings.ToLower(domain)
	if domain == "" {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	if err := dms.graph.InsertMX(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s failed to insert MX record: %v", dms.graph, err))
	}

	if target != domain {
		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}
}

func (dms *DataManagerService) insertTXT(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return
	}

	if !cfg.IsDomainInScope(req.Name) {
		return
	}

	dms.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain)
}

func (dms *DataManagerService) insertSOA(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return
	}

	if !cfg.IsDomainInScope(req.Name) {
		return
	}

	dms.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain)
}

func (dms *DataManagerService) insertSPF(ctx context.Context, req *requests.DNSRequest, recidx int) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	if cfg == nil {
		return
	}

	if !cfg.IsDomainInScope(req.Name) {
		return
	}

	dms.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain)
}

func (dms *DataManagerService) findNamesAndAddresses(ctx context.Context, data, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, dms.String())

	ipre := regexp.MustCompile(net.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		bus.Publish(requests.NewAddrTopic, eventbus.PriorityHigh, &requests.AddrRequest{
			Address: ip,
			Domain:  domain,
			Tag:     requests.DNS,
			Source:  "DNS",
		})
	}

	subre := amassdns.AnySubdomainRegex()
	for _, name := range subre.FindAllString(data, -1) {
		domain := strings.ToLower(cfg.WhichDomain(name))
		if domain == "" {
			continue
		}

		bus.Publish(requests.NewNameTopic, eventbus.PriorityHigh, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}
}
