// Copyright 2017-2021 Jeff Foley. All rights reserved.
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

	amassnet "github.com/OWASP/Amass/v3/net"
	amassdns "github.com/OWASP/Amass/v3/net/dns"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/eventbus"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/caffix/resolve"
	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// dataManager is the stage that stores all data processed by the pipeline.
type dataManager struct {
	enum  *Enumeration
	queue queue.Queue
}

// newDataManager returns a dataManager specific to the provided Enumeration.
func newDataManager(e *Enumeration) *dataManager {
	dm := &dataManager{
		enum:  e,
		queue: queue.NewQueue(),
	}

	go dm.processASNRequests()
	return dm
}

// Process implements the pipeline Task interface.
func (dm *dataManager) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	_, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return data, nil
	}

	switch v := data.(type) {
	case *requests.DNSRequest:
		if v == nil {
			return nil, nil
		}
		if err := dm.dnsRequest(ctx, v, tp); err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, err.Error())
		}
	case *requests.AddrRequest:
		if v == nil {
			return nil, nil
		}
		if err := dm.addrRequest(ctx, v, tp); err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, err.Error())
		}
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
		select {
		case <-ctx.Done():
			return nil
		default:
		}

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
	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	target := resolve.RemoveLastDot(req.Records[recidx].Data)
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

	if err := dm.enum.Graph.UpsertCNAME(req.Name, target, req.Source, cfg.UUID.String()); err != nil {
		return fmt.Errorf("%s failed to insert CNAME: %v", dm.enum.Graph, err)
	}

	// Important - Allows chained CNAME records to be resolved until an A/AAAA record
	pipeline.SendData(ctx, "new", &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return errors.New("Failed to extract an IP address from the DNS answer data")
	}

	if err := dm.enum.Graph.UpsertA(req.Name, addr, req.Source, cfg.UUID.String()); err != nil {
		return fmt.Errorf("%s failed to insert A record: %v", dm.enum.Graph, err)
	}

	pipeline.SendData(ctx, "new", &requests.AddrRequest{
		Address: addr,
		InScope: true,
		Domain:  req.Domain,
		Tag:     requests.DNS,
		Source:  "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertAAAA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return errors.New("Failed to extract an IP address from the DNS answer data")
	}

	if err := dm.enum.Graph.UpsertAAAA(req.Name, addr, req.Source, cfg.UUID.String()); err != nil {
		return fmt.Errorf("%s failed to insert AAAA record: %v", dm.enum.Graph, err)
	}

	pipeline.SendData(ctx, "new", &requests.AddrRequest{
		Address: addr,
		InScope: true,
		Domain:  req.Domain,
		Tag:     requests.DNS,
		Source:  "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertPTR(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	target := resolve.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return errors.New("Failed to extract a FQDN from the DNS answer data")
	}

	// Do not go further if the target is not in scope
	domain := strings.ToLower(cfg.WhichDomain(target))
	if domain == "" {
		return nil
	}

	if err := dm.enum.Graph.UpsertPTR(req.Name, target, req.Source, cfg.UUID.String()); err != nil {
		return fmt.Errorf("%s failed to insert PTR record: %v", dm.enum.Graph, err)
	}

	// Important - Allows the target DNS name to be resolved in the forward direction
	pipeline.SendData(ctx, "new", &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "DNS",
	}, tp)
	return nil
}

func (dm *dataManager) insertSRV(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	service := resolve.RemoveLastDot(req.Records[recidx].Name)
	target := resolve.RemoveLastDot(req.Records[recidx].Data)
	if target == "" || service == "" {
		return errors.New("Failed to extract service info from the DNS answer data")
	}

	if err := dm.enum.Graph.UpsertSRV(req.Name, service, target, req.Source, cfg.UUID.String()); err != nil {
		return fmt.Errorf("%s failed to insert SRV record: %v", dm.enum.Graph, err)
	}

	if domain := cfg.WhichDomain(target); domain != "" {
		pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
	return nil
}

func (dm *dataManager) insertNS(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := requests.ContextConfigBus(ctx)
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

	if err := dm.enum.Graph.UpsertNS(req.Name, target, req.Source, cfg.UUID.String()); err != nil {
		return fmt.Errorf("%s failed to insert NS record: %v", dm.enum.Graph, err)
	}

	if target != domain {
		pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
	return nil
}

func (dm *dataManager) insertMX(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return errors.New("The context did not contain the expected values")
	}

	target := resolve.RemoveLastDot(req.Records[recidx].Data)
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

	if err := dm.enum.Graph.UpsertMX(req.Name, target, req.Source, cfg.UUID.String()); err != nil {
		return fmt.Errorf("%s failed to insert MX record: %v", dm.enum.Graph, err)
	}

	if target != domain {
		pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
	return nil
}

func (dm *dataManager) insertTXT(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	cfg, _, err := requests.ContextConfigBus(ctx)
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
	cfg, _, err := requests.ContextConfigBus(ctx)
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
	cfg, _, err := requests.ContextConfigBus(ctx)
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
		pipeline.SendData(ctx, "new", &requests.AddrRequest{
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

		pipeline.SendData(ctx, "new", &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "DNS",
		}, tp)
	}
}

type queuedAddrRequest struct {
	Req *requests.AddrRequest
	Tp  pipeline.TaskParams
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

	if yes, prefix := amassnet.IsReservedAddress(req.Address); yes {
		return graph.UpsertInfrastructure(0, amassnet.ReservedCIDRDescription, req.Address, prefix, "RIR", uuid)
	}

	if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
		return graph.UpsertInfrastructure(r.ASN, r.Description, req.Address, r.Prefix, r.Source, uuid)
	}

	// Hold the pipeline during slow activities
	tp.NewData() <- req
	dm.queue.Append(&queuedAddrRequest{
		Req: req,
		Tp:  tp,
	})
	return nil
}

func (dm *dataManager) processASNRequests() {
	graph := dm.enum.Graph
	uuid := dm.enum.Config.UUID.String()
loop:
	for {
		select {
		case <-dm.enum.ctx.Done():
			break loop
		case <-dm.enum.done:
			break loop
		case <-dm.queue.Signal():
			e, found := dm.queue.Next()
			if !found {
				continue loop
			}

			qar, ok := e.(*queuedAddrRequest)
			if !ok {
				continue loop
			}
			req := qar.Req
			tp := qar.Tp

			if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
				_ = graph.UpsertInfrastructure(r.ASN, r.Description, req.Address, r.Prefix, r.Source, uuid)
				tp.ProcessedData() <- req
				continue loop
			}

			for _, src := range dm.enum.srcs {
				src.Request(dm.enum.ctx, &requests.ASNRequest{Address: req.Address})
			}
			time.Sleep(10 * time.Second)

			if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
				_ = graph.UpsertInfrastructure(r.ASN, r.Description, req.Address, r.Prefix, r.Source, uuid)
				tp.ProcessedData() <- req
				continue loop
			}

			asn := 0
			desc := "Unknown"
			prefix := fakePrefix(req.Address)
			_ = graph.UpsertInfrastructure(asn, desc, req.Address, prefix, "RIR", uuid)

			first, cidr, err := net.ParseCIDR(prefix)
			if err != nil {
				tp.ProcessedData() <- req
				continue loop
			}
			if ones, _ := cidr.Mask.Size(); ones == 0 {
				tp.ProcessedData() <- req
				continue loop
			}

			dm.enum.Sys.Cache().Update(&requests.ASNRequest{
				Address:     first.String(),
				ASN:         asn,
				Prefix:      cidr.String(),
				Description: desc,
				Tag:         requests.RIR,
				Source:      "RIR",
			})
			tp.ProcessedData() <- req
		}
	}

	// Empty the queue
	dm.queue.Process(func(e interface{}) {
		if q, ok := e.(*queuedAddrRequest); ok {
			q.Tp.ProcessedData() <- q.Req
		}
	})
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
