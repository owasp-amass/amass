// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"github.com/miekg/dns"
	amassnet "github.com/owasp-amass/amass/v4/net"
	amassdns "github.com/owasp-amass/amass/v4/net/dns"
	"github.com/owasp-amass/amass/v4/requests"
	"github.com/owasp-amass/resolve"
	bf "github.com/tylertreat/BoomFilters"
	"golang.org/x/net/publicsuffix"
)

// dataManager is the stage that stores all data processed by the pipeline.
type dataManager struct {
	enum        *Enumeration
	queue       queue.Queue
	signalDone  chan struct{}
	confirmDone chan struct{}
	filter      *bf.StableBloomFilter
}

// newDataManager returns a dataManager specific to the provided Enumeration.
func newDataManager(e *Enumeration) *dataManager {
	dm := &dataManager{
		enum:        e,
		queue:       queue.NewQueue(),
		signalDone:  make(chan struct{}, 2),
		confirmDone: make(chan struct{}, 2),
		filter:      bf.NewDefaultStableBloomFilter(1000000, 0.01),
	}

	go dm.processASNRequests()
	return dm
}

func (dm *dataManager) Stop() chan struct{} {
	dm.filter.Reset()
	close(dm.signalDone)
	return dm.confirmDone
}

// Process implements the pipeline Task interface.
func (dm *dataManager) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	var id string
	switch v := data.(type) {
	case *requests.DNSRequest:
		if v == nil {
			return nil, nil
		}

		id = v.Name
		if err := dm.dnsRequest(ctx, v, tp); err != nil {
			dm.enum.Config.Log.Print(err.Error())
		}
	case *requests.AddrRequest:
		if v == nil {
			return nil, nil
		}

		id = v.Address
		if err := dm.addrRequest(ctx, v, tp); err != nil {
			dm.enum.Config.Log.Print(err.Error())
		}
	}

	if id != "" && dm.filter.TestAndAdd([]byte(id)) {
		return nil, nil
	}
	return data, nil
}

func (dm *dataManager) dnsRequest(ctx context.Context, req *requests.DNSRequest, tp pipeline.TaskParams) error {
	if dm.enum.Config.Blacklisted(req.Name) {
		return nil
	}
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

		var e error
		switch uint16(r.Type) {
		case dns.TypeA:
			e = dm.insertA(ctx, req, i, tp)
		case dns.TypeAAAA:
			e = dm.insertAAAA(ctx, req, i, tp)
		case dns.TypePTR:
			e = dm.insertPTR(ctx, req, i, tp)
		case dns.TypeSRV:
			e = dm.insertSRV(ctx, req, i, tp)
		case dns.TypeNS:
			e = dm.insertNS(ctx, req, i, tp)
		case dns.TypeMX:
			e = dm.insertMX(ctx, req, i, tp)
		case dns.TypeTXT:
			e = dm.insertTXT(ctx, req, i, tp)
		case dns.TypeSOA:
			e = dm.insertSOA(ctx, req, i, tp)
		case dns.TypeSPF:
			e = dm.insertSPF(ctx, req, i, tp)
		}
		if err == nil {
			err = e
		}
	}
	return err
}

func (dm *dataManager) insertCNAME(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	target := resolve.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return errors.New("failed to extract a FQDN from the DNS answer data")
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil || domain == "" {
		return errors.New("failed to extract a domain name from the FQDN")
	}
	// Important - Allows chained CNAME records to be resolved until an A/AAAA record
	dm.enum.nameSrc.newName(&requests.DNSRequest{
		Name:   target,
		Domain: strings.ToLower(domain),
	})
	if err := dm.enum.graph.UpsertCNAME(ctx, req.Name, target); err != nil {
		return fmt.Errorf("failed to insert CNAME: %v", err)
	}
	return nil
}

func (dm *dataManager) insertA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return errors.New("failed to extract an IP address from the DNS answer data")
	}
	dm.enum.checkForMissedWildcards(addr)
	dm.enum.nameSrc.newAddr(&requests.AddrRequest{
		Address: addr,
		InScope: true,
		Domain:  req.Domain,
	})
	if err := dm.enum.graph.UpsertA(ctx, req.Name, addr); err != nil {
		return fmt.Errorf("failed to insert A record: %v", err)
	}
	return nil
}

func (dm *dataManager) insertAAAA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return errors.New("failed to extract an IP address from the DNS answer data")
	}
	dm.enum.checkForMissedWildcards(addr)
	dm.enum.nameSrc.newAddr(&requests.AddrRequest{
		Address: addr,
		InScope: true,
		Domain:  req.Domain,
	})
	if err := dm.enum.graph.UpsertAAAA(ctx, req.Name, addr); err != nil {
		return fmt.Errorf("failed to insert AAAA record: %v", err)
	}
	return nil
}

func (dm *dataManager) insertPTR(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	target := resolve.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return errors.New("failed to extract a FQDN from the DNS answer data")
	}
	// Do not go further if the target is not in scope
	domain := strings.ToLower(dm.enum.Config.WhichDomain(target))
	if domain == "" {
		return nil
	}
	// Important - Allows the target DNS name to be resolved in the forward direction
	dm.enum.nameSrc.newName(&requests.DNSRequest{
		Name:   target,
		Domain: domain,
	})
	if err := dm.enum.graph.UpsertPTR(ctx, req.Name, target); err != nil {
		return fmt.Errorf("failed to insert PTR record: %v", err)
	}
	return nil
}

func (dm *dataManager) insertSRV(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	service := resolve.RemoveLastDot(req.Records[recidx].Name)
	target := resolve.RemoveLastDot(req.Records[recidx].Data)
	if target == "" || service == "" {
		return errors.New("failed to extract service info from the DNS answer data")
	}
	if domain := dm.enum.Config.WhichDomain(target); domain != "" {
		dm.enum.nameSrc.newName(&requests.DNSRequest{
			Name:   target,
			Domain: domain,
		})
	}
	if err := dm.enum.graph.UpsertSRV(ctx, service, target); err != nil {
		return fmt.Errorf("failed to insert SRV record: %v", err)
	}
	return nil
}

func (dm *dataManager) insertNS(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	target := req.Records[recidx].Data
	if target == "" {
		return errors.New("failed to extract NS info from the DNS answer data")
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil || domain == "" {
		return errors.New("failed to extract a domain name from the FQDN")
	}
	if d := strings.ToLower(domain); target != d {
		dm.enum.nameSrc.newName(&requests.DNSRequest{
			Name:   target,
			Domain: d,
		})
	}
	if err := dm.enum.graph.UpsertNS(ctx, req.Name, target); err != nil {
		return fmt.Errorf("failed to insert NS record: %v", err)
	}
	return nil
}

func (dm *dataManager) insertMX(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	target := resolve.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return errors.New("failed to extract a FQDN from the DNS answer data")
	}

	domain, err := publicsuffix.EffectiveTLDPlusOne(target)
	if err != nil || domain == "" {
		return errors.New("failed to extract a domain name from the FQDN")
	}
	if d := strings.ToLower(domain); target != d {
		dm.enum.nameSrc.newName(&requests.DNSRequest{
			Name:   target,
			Domain: d,
		})
	}
	if err := dm.enum.graph.UpsertMX(ctx, req.Name, target); err != nil {
		return fmt.Errorf("failed to insert MX record: %v", err)
	}
	return nil
}

func (dm *dataManager) insertTXT(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	if dm.enum.Config.IsDomainInScope(req.Name) {
		dm.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain, tp)
	}
	return nil
}

func (dm *dataManager) insertSOA(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	if dm.enum.Config.IsDomainInScope(req.Name) {
		dm.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain, tp)
	}
	return nil
}

func (dm *dataManager) insertSPF(ctx context.Context, req *requests.DNSRequest, recidx int, tp pipeline.TaskParams) error {
	if dm.enum.Config.IsDomainInScope(req.Name) {
		dm.findNamesAndAddresses(ctx, req.Records[recidx].Data, req.Domain, tp)
	}
	return nil
}

func (dm *dataManager) findNamesAndAddresses(ctx context.Context, data, domain string, tp pipeline.TaskParams) {
	ipre := regexp.MustCompile(amassnet.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		dm.enum.nameSrc.newAddr(&requests.AddrRequest{
			Address: ip,
			Domain:  domain,
		})
	}

	subre := amassdns.AnySubdomainRegex()
	for _, name := range subre.FindAllString(data, -1) {
		if domain := strings.ToLower(dm.enum.Config.WhichDomain(name)); domain != "" {
			dm.enum.nameSrc.newName(&requests.DNSRequest{
				Name:   name,
				Domain: domain,
			})
		}
	}
}

func (dm *dataManager) addrRequest(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) error {
	select {
	case <-ctx.Done():
		return nil
	default:
	}

	if req == nil || !req.InScope {
		return nil
	}
	if yes, prefix := amassnet.IsReservedAddress(req.Address); yes {
		var err error
		if e := dm.enum.graph.UpsertInfrastructure(ctx, 0, amassnet.ReservedCIDRDescription, req.Address, prefix); e != nil {
			err = e
		}
		return err
	}
	if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
		var err error
		if e := dm.enum.graph.UpsertInfrastructure(ctx, r.ASN, r.Description, req.Address, r.Prefix); e != nil {
			err = e
		}
		return err
	}

	dm.queue.Append(req)
	return nil
}

func (dm *dataManager) processASNRequests() {
loop:
	for {
		select {
		case <-dm.signalDone:
			if dm.queue.Len() == 0 {
				break loop
			}
			dm.nextInfraInfo()
		case <-dm.queue.Signal():
			dm.nextInfraInfo()
		}
	}
	close(dm.confirmDone)
}

func (dm *dataManager) nextInfraInfo() {
	e, ok := dm.queue.Next()
	if !ok {
		return
	}

	ctx := context.Background()
	req := e.(*requests.AddrRequest)
	if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
		_ = dm.enum.graph.UpsertInfrastructure(ctx, r.ASN, r.Description, req.Address, r.Prefix)
		return
	}

	dm.enum.sendRequests(&requests.ASNRequest{Address: req.Address})
loop:
	for i := 0; i < 30; i++ {
		select {
		case <-dm.enum.ctx.Done():
			break loop
		default:
		}

		time.Sleep(2 * time.Second)
		if r := dm.enum.Sys.Cache().AddrSearch(req.Address); r != nil {
			_ = dm.enum.graph.UpsertInfrastructure(ctx, r.ASN, r.Description, req.Address, r.Prefix)
			return
		}
	}

	asn := 0
	desc := "Unknown"
	prefix := fakePrefix(req.Address)
	_ = dm.enum.graph.UpsertInfrastructure(ctx, asn, desc, req.Address, prefix)

	first, cidr, _ := net.ParseCIDR(prefix)
	dm.enum.Sys.Cache().Update(&requests.ASNRequest{
		Address:     first.String(),
		ASN:         asn,
		Prefix:      cidr.String(),
		Description: desc,
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
