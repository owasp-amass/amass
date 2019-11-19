// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/OWASP/Amass/v3/semaphore"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// DataManagerService is the Service that handles all data collected
// within the architecture. This is achieved by watching all the RESOLVED events.
type DataManagerService struct {
	BaseService

	maxRequests semaphore.Semaphore
}

// NewDataManagerService returns he object initialized, but not yet started.
func NewDataManagerService(sys System) *DataManagerService {
	dms := &DataManagerService{maxRequests: semaphore.NewSimpleSemaphore(25)}

	dms.BaseService = *NewBaseService(dms, "Data Manager", sys)
	return dms
}

// OnDNSRequest implements the Service interface.
func (dms *DataManagerService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}
	bus.Publish(requests.SetActiveTopic, dms.String())

	// Check for CNAME records first
	for i, r := range req.Records {
		req.Records[i].Name = strings.Trim(strings.ToLower(r.Name), ".")
		req.Records[i].Data = strings.Trim(strings.ToLower(r.Data), ".")

		if uint16(r.Type) == dns.TypeCNAME {
			dms.maxRequests.Acquire(1)
			go dms.insertCNAME(ctx, req, i)
			// Do not enter more than the CNAME record
			return
		}
	}

	for i, r := range req.Records {
		req.Records[i].Name = strings.Trim(strings.ToLower(r.Name), ".")
		req.Records[i].Data = strings.Trim(strings.ToLower(r.Data), ".")

		dms.maxRequests.Acquire(1)
		bus.Publish(requests.SetActiveTopic, dms.String())

		switch uint16(r.Type) {
		case dns.TypeA:
			go dms.insertA(ctx, req, i)
		case dns.TypeAAAA:
			go dms.insertAAAA(ctx, req, i)
		case dns.TypePTR:
			go dms.insertPTR(ctx, req, i)
		case dns.TypeSRV:
			go dms.insertSRV(ctx, req, i)
		case dns.TypeNS:
			go dms.insertNS(ctx, req, i)
		case dns.TypeMX:
			go dms.insertMX(ctx, req, i)
		case dns.TypeTXT:
			go dms.insertTXT(ctx, req, i)
		case dns.TypeSPF:
			go dms.insertSPF(ctx, req, i)
		default:
			dms.maxRequests.Release(1)
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

	for _, g := range dms.System().GraphDatabases() {
		err := g.InsertInfrastructure(req.ASN, req.Description,
			req.Address, req.Prefix, req.Source, req.Tag, cfg.UUID.String())
		if err != nil {
			bus.Publish(requests.LogTopic,
				fmt.Sprintf("%s: %s failed to insert infrastructure data: %v", dms.String(), g, err),
			)
		}
	}

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertCNAME(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

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

	for _, g := range dms.System().GraphDatabases() {
		if err := g.InsertCNAME(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert CNAME: %v", g, err))
		}
	}

	// Important - Allows chained CNAME records to be resolved until an A/AAAA record
	bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "DNS",
	})

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertA(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return
	}

	for _, g := range dms.System().GraphDatabases() {
		if err := g.InsertA(req.Name, addr, req.Source, req.Tag, cfg.UUID.String()); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert A record: %v", g, err))
		}
	}

	bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
		Address: addr,
		Domain:  req.Domain,
		Tag:     req.Tag,
		Source:  req.Source,
	})

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertAAAA(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return
	}

	for _, g := range dms.System().GraphDatabases() {
		if err := g.InsertA(req.Name, addr, req.Source, req.Tag, cfg.UUID.String()); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert AAAA record: %v", g, err))
		}
	}

	bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
		Address: addr,
		Domain:  req.Domain,
		Tag:     req.Tag,
		Source:  req.Source,
	})

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertPTR(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

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

	for _, g := range dms.System().GraphDatabases() {
		if err := g.InsertPTR(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert PTR record: %v", g, err))
		}
	}

	bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: req.Source,
	})

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertSRV(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

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

	for _, g := range dms.System().GraphDatabases() {
		if err := g.InsertSRV(req.Name, service, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert SRV record: %v", g, err))
		}
	}

	if domain := cfg.WhichDomain(target); domain != "" {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    req.Tag,
			Source: req.Source,
		})
	}

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertNS(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

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

	for _, g := range dms.System().GraphDatabases() {
		if err := g.InsertNS(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert NS record: %v", g, err))
		}
	}

	if target != domain {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertMX(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

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

	for _, g := range dms.System().GraphDatabases() {
		if err := g.InsertMX(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert MX record: %v", g, err))
		}
	}

	if target != domain {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}

	bus.Publish(requests.SetActiveTopic, dms.String())
}

func (dms *DataManagerService) insertTXT(ctx context.Context, req *requests.DNSRequest, recidx int) {
	defer dms.maxRequests.Release(1)

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
	defer dms.maxRequests.Release(1)

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

	ipre := regexp.MustCompile(net.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Domain:  domain,
			Tag:     requests.DNS,
			Source:  "DNS",
		})
	}

	subre := amassdns.AnySubdomainRegex()
	for _, name := range subre.FindAllString(data, -1) {
		if !cfg.IsDomainInScope(name) {
			continue
		}

		domain := strings.ToLower(cfg.WhichDomain(name))
		if domain == "" {
			continue
		}

		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		})
	}

	bus.Publish(requests.SetActiveTopic, dms.String())
}
