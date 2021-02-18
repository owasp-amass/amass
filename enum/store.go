// Copyright 2017-2020 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package enum

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/datasrcs"
	amassnet "github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/resolvers"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// DataManager is the OutputSink that handles all data processed by the pipeline.
type dataManager struct {
	enum *Enumeration
}

// newDataManager returns a dataManager specific to the provided Enumeration.
func newDataManager(e *Enumeration) *dataManager {
	return &dataManager{enum: e}
}

// Process implements the pipeline Task interface.
func (dm *dataManager) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	switch v := data.(type) {
	case *requests.DNSRequest:
		if v == nil {
			return nil, nil
		}
		return data, dm.dnsRequest(ctx, v, tp)
	case *requests.AddrRequest:
		if v == nil {
			return nil, nil
		}
		return data, dm.addrRequest(ctx, v, tp)
	}

	return data, nil
}

func (dm *dataManager) dnsRequest(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) error {
	// Check for CNAME records first
	for i, r := range req.Records {
		req.Records[i].Name = strings.Trim(strings.ToLower(r.Name), ".")
		req.Records[i].Data = strings.Trim(strings.ToLower(r.Data), ".")

		if uint16(r.Type) == dns.TypeCNAME {
			// Do not enter more than the CNAME record
			return dm.insertCNAME(ctx, req, i, tp)
		}
	}

	var err error
	for i, r := range req.Records {
		switch uint16(r.Type) {
		case dns.TypeA:
			err = dm.insertA(ctx, req, i, tp)
		case dns.TypeAAAA:
			err = dm.insertAAAA(ctx, req, i, tp)
		case dns.TypePTR:
			err = dm.insertPTR(ctx, req, i, tp)
		case dns.TypeSRV:
			err = dm.insertSRV(ctx, req, i, tp)
		case dns.TypeNS:
			err = dm.insertNS(ctx, req, i, tp)
		case dns.TypeMX:
			err = dm.insertMX(ctx, req, i, tp)
		case dns.TypeTXT:
			err = dm.insertTXT(ctx, req, i, tp)
		case dns.TypeSOA:
			err = dm.insertSOA(ctx, req, i, tp)
		case dns.TypeSPF:
			err = dm.insertSPF(ctx, req, i, tp)
		}
		if err != nil {
			break
		}
	}
	return err
}

func (dm *dataManager) insertCNAME(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return errors.New("Failed to extract a FQDN from the DNS answer data")
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		return errors.New("Failed to extract a domain name from the FQDN")
	}

	domain = strings.ToLower(domain)
	if domain == "" {
		return errors.New("The request did not contain a domain name")
	}

	if err := dm.enum.Graph.InsertCNAME(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		msg := fmt.Sprintf("%s failed to insert CNAME: %v", dm.enum.Graph, err)

		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, msg)
		return errors.New(msg)
	}

	// Important - Allows chained CNAME records to be resolved until an A/AAAA record
	go pipeline.SendData(ctx, "new", &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return errors.New("Failed to extract an IP address from the DNS answer data")
	}

	if err := dm.enum.Graph.InsertA(req.Name, addr, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		msg := fmt.Sprintf("%s failed to insert A record: %v", dm.enum.Graph, err)

		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, msg)
		return errors.New(msg)
	}

	go pipeline.SendData(ctx, "new", &requests.AddrRequest{
		Address: addr,
		InScope: true,
		Domain:  req.Domain,
		Tag:     requests.DNS,
		Source:  "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertAAAA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return errors.New("Failed to extract an IP address from the DNS answer data")
	}

	if err := dm.enum.Graph.InsertAAAA(req.Name, addr, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		msg := fmt.Sprintf("%s failed to insert AAAA record: %v", dm.enum.Graph, err)

		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, msg)
		return errors.New(msg)
	}

	go pipeline.SendData(ctx, "new", &requests.AddrRequest{
		Address: addr,
		InScope: true,
		Domain:  req.Domain,
		Tag:     requests.DNS,
		Source:  "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertPTR(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return errors.New("Failed to extract a FQDN from the DNS answer data")
	}

	// Do not go further if the target is not in scope
	domain := strings.ToLower(cfg.WhichDomain(target))
	if domain == "" {
		return nil
	}

	if err := dm.enum.Graph.InsertPTR(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		msg := fmt.Sprintf("%s failed to insert PTR record: %v", dm.enum.Graph, err)

		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, msg)
		return errors.New(msg)
	}

	// Important - Allows the target DNS name to be resolved in the forward direction
	go pipeline.SendData(ctx, "new", &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertSRV(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	service := resolvers.RemoveLastDot(req.Records[recidx].Name)
	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" || service == "" {
		return errors.New("Failed to extract service info from the DNS answer data")
	}

	if err := dm.enum.Graph.InsertSRV(req.Name, service, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		msg := fmt.Sprintf("%s failed to insert SRV record: %v", dm.enum.Graph, err)

		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, msg)
		return errors.New(msg)
	}

	if domain := cfg.WhichDomain(target); domain != "" {
		go pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
	return nil
}

func (dm *dataManager) insertNS(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	target := req.Records[recidx].Data
	if target == "" {
		return errors.New("Failed to extract NS info from the DNS answer data")
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		return errors.New("Failed to extract a domain name from the FQDN")
	}

	domain = strings.ToLower(domain)
	if domain == "" {
		return errors.New("The request did not contain a domain name")
	}

	if err := dm.enum.Graph.InsertNS(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		msg := fmt.Sprintf("%s failed to insert NS record: %v", dm.enum.Graph, err)

		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, msg)
		return errors.New(msg)
	}

	if target != domain {
		go pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
	return nil
}

func (dm *dataManager) insertMX(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, bus, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return errors.New("Failed to extract a FQDN from the DNS answer data")
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil {
		return errors.New("Failed to extract a domain name from the FQDN")
	}

	domain = strings.ToLower(domain)
	if domain == "" {
		return errors.New("The request did not contain a domain name")
	}

	if err := dm.enum.Graph.InsertMX(req.Name, target, req.Source, req.Tag, cfg.UUID.String()); err != nil {
		msg := fmt.Sprintf("%s failed to insert MX record: %v", dm.enum.Graph, err)

		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, msg)
		return errors.New(msg)
	}

	if target != domain {
		go pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
	return nil
}

func (dm *dataManager) insertTXT(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	if !cfg.IsDomainInScope(req.Name) {
		return nil
	}

	dm.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain, tp)
	return nil
}

func (dm *dataManager) insertSOA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	if !cfg.IsDomainInScope(req.Name) {
		return nil
	}

	dm.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain, tp)
	return nil
}

func (dm *dataManager) insertSPF(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := datasrcs.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	if !cfg.IsDomainInScope(req.Name) {
		return nil
	}

	dm.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain, tp)
	return nil
}

func (dm *dataManager) findNamesAndAddresses(ctx context.Context, data, domain string, tp pipeline.TaskParams) {
	ipre := regexp.MustCompile(amassnet.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		go pipeline.SendData(ctx, "new", &requests.AddrRequest{
			Address: ip,
			Domain:  domain,
			Tag:     requests.DNS,
			Source:  "DNS",
		}, tp)
	}

	subre := amassdns.AnySubdomainRegex()
	for _, name := range subre.FindAllString(data, -1) {
		domain := strings.ToLower(dm.enum.Config.WhichDomain(name))
		if domain == "" {
			continue
		}

		go pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
}

func (dm *dataManager) addrRequest(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) error {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	graph := dm.enum.Graph
	uuid := dm.enum.Config.UUID.String()
	if req == nil || !req.InScope || graph == nil || uuid == "" {
		return nil
	}

	if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
		return graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, uuid)
	}

	for _, src := range dm.enum.srcs {
		src.Request(ctx, &requests.ASNRequest{Address: req.Address})
	}

	var err error
	var found bool
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for i := 0; i < 10; i++ {
		select {
		case <-ctx.Done():
			return nil
		case <-t.C:
			if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
				err = graph.InsertInfrastructure(r.ASN, r.Description, r.Address, r.Prefix, r.Source, r.Tag, uuid)
				found = true
				break loop
			}
		}
	}

	if !found {
		err = graph.InsertInfrastructure(0, "Unknown", req.Address, fakePrefix(req.Address), "RIR", requests.RIR, uuid)
	}
	if err != nil {
		return err
	}
	return graph.HealAddressNodes(dm.enum.Sys.Cache(), uuid)
}

func fakePrefix(addr string) string {
	bits := 24
	total := 32
	ip := net.ParseIP(addr)

	if amassnet.IsIPv6(ip) {
		bits = 48
		total = 128
	}

	mask := net.CIDRMask(bits, total)
	return fmt.Sprintf("%s/%d", ip.Mask(mask).String(), bits)
}
