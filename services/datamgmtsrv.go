// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/graph"
	"github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/miekg/dns"
)

// DataManagerService is the Service that handles all data collected
// within the architecture. This is achieved by watching all the RESOLVED events.
type DataManagerService struct {
	BaseService
}

// NewDataManagerService returns he object initialized, but not yet started.
func NewDataManagerService(sys System) *DataManagerService {
	dms := new(DataManagerService)

	dms.BaseService = *NewBaseService(dms, "Data Manager", sys)
	return dms
}

// OnDNSRequest implements the Service interface.
func (dms *DataManagerService) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	req.Name = strings.ToLower(req.Name)
	req.Domain = strings.ToLower(req.Domain)

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}
	bus.Publish(requests.SetActiveTopic, dms.String())

	dms.insertDomain(ctx, req.Domain)
	for i, r := range req.Records {
		req.Records[i].Name = strings.ToLower(r.Name)
		req.Records[i].Data = strings.ToLower(r.Data)

		switch uint16(r.Type) {
		case dns.TypeA:
			dms.insertA(ctx, req, i)
		case dns.TypeAAAA:
			dms.insertAAAA(ctx, req, i)
		case dns.TypeCNAME:
			dms.insertCNAME(ctx, req, i)
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

	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:        cfg.UUID.String(),
			Timestamp:   time.Now().Format(time.RFC3339),
			Type:        graph.OptInfrastructure,
			Address:     req.Address,
			ASN:         req.ASN,
			CIDR:        req.Prefix,
			Description: req.Description,
		})
		if err != nil {
			bus.Publish(requests.LogTopic,
				fmt.Sprintf("%s: %s failed to insert infrastructure data: %v", dms.String(), g, err),
			)
		}
	}
}

func (dms *DataManagerService) insertDomain(ctx context.Context, domain string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	domain = strings.ToLower(domain)
	if domain == "" {
		return
	}

	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:      cfg.UUID.String(),
			Timestamp: time.Now().Format(time.RFC3339),
			Type:      graph.OptDomain,
			Domain:    domain,
			Tag:       requests.DNS,
			Source:    "Forward DNS",
		})
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert domain: %v", g, err))
		}
	}

	bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   domain,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "Forward DNS",
	})
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

	domain := strings.ToLower(dms.System().Pool().SubdomainToDomain(target))
	if domain == "" {
		return
	}

	dms.insertDomain(ctx, domain)
	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:         cfg.UUID.String(),
			Timestamp:    time.Now().Format(time.RFC3339),
			Type:         graph.OptCNAME,
			Name:         req.Name,
			Domain:       req.Domain,
			TargetName:   target,
			TargetDomain: domain,
			Tag:          req.Tag,
			Source:       req.Source,
		})
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert CNAME: %v", g, err))
		}
	}

	// Important - Allows chained CNAME records to be resolved until an A/AAAA record
	bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "Forward DNS",
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

	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:      cfg.UUID.String(),
			Timestamp: time.Now().Format(time.RFC3339),
			Type:      graph.OptA,
			Name:      req.Name,
			Domain:    req.Domain,
			Address:   addr,
			Tag:       req.Tag,
			Source:    req.Source,
		})
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert A record: %v", g, err))
		}
	}

	bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
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

	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:      cfg.UUID.String(),
			Timestamp: time.Now().Format(time.RFC3339),
			Type:      graph.OptAAAA,
			Name:      req.Name,
			Domain:    req.Domain,
			Address:   addr,
			Tag:       req.Tag,
			Source:    req.Source,
		})
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert AAAA record: %v", g, err))
		}
	}

	bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
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

	dms.insertDomain(ctx, domain)
	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:       cfg.UUID.String(),
			Timestamp:  time.Now().Format(time.RFC3339),
			Type:       graph.OptPTR,
			Name:       req.Name,
			Domain:     domain,
			TargetName: target,
			Tag:        req.Tag,
			Source:     req.Source,
		})
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert PTR record: %v", g, err))
		}
	}

	bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
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

	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:       cfg.UUID.String(),
			Timestamp:  time.Now().Format(time.RFC3339),
			Type:       graph.OptSRV,
			Name:       req.Name,
			Domain:     req.Domain,
			Service:    service,
			TargetName: target,
			Tag:        req.Tag,
			Source:     req.Source,
		})
		if err != nil {
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

	domain := strings.ToLower(dms.System().Pool().SubdomainToDomain(target))
	if domain == "" {
		return
	}

	dms.insertDomain(ctx, domain)
	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:         cfg.UUID.String(),
			Timestamp:    time.Now().Format(time.RFC3339),
			Type:         graph.OptNS,
			Name:         req.Name,
			Domain:       req.Domain,
			TargetName:   target,
			TargetDomain: domain,
			Tag:          req.Tag,
			Source:       req.Source,
		})
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert NS record: %v", g, err))
		}
	}

	if target != domain {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "Forward DNS",
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

	domain := strings.ToLower(dms.System().Pool().SubdomainToDomain(target))
	if domain == "" {
		return
	}

	dms.insertDomain(ctx, domain)
	for _, g := range dms.System().GraphDatabases() {
		err := g.Insert(&graph.DataOptsParams{
			UUID:         cfg.UUID.String(),
			Timestamp:    time.Now().Format(time.RFC3339),
			Type:         graph.OptMX,
			Name:         req.Name,
			Domain:       req.Domain,
			TargetName:   target,
			TargetDomain: domain,
			Tag:          req.Tag,
			Source:       req.Source,
		})
		if err != nil {
			bus.Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert MX record: %v", g, err))
		}
	}

	if target != domain {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "Forward DNS",
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

	ipre := regexp.MustCompile(net.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Domain:  domain,
			Tag:     requests.DNS,
			Source:  "Forward DNS",
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
			Source: "Forward DNS",
		})
	}
}
