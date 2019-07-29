// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/graph"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/utils"
	"github.com/miekg/dns"
)

// DataManagerService is the Service that handles all data collected
// within the architecture. This is achieved by watching all the RESOLVED events.
type DataManagerService struct {
	BaseService

	Handlers     []graph.DataHandler
	domainFilter *utils.StringFilter
}

// NewDataManagerService returns he object initialized, but not yet started.
func NewDataManagerService(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *DataManagerService {
	dms := &DataManagerService{domainFilter: utils.NewStringFilter()}

	dms.BaseService = *NewBaseService(dms, "Data Manager", cfg, bus, pool)
	return dms
}

// OnStart implements the Service interface
func (dms *DataManagerService) OnStart() error {
	dms.BaseService.OnStart()

	dms.Bus().Subscribe(requests.NameResolvedTopic, dms.SendDNSRequest)
	go dms.processRequests()
	return nil
}

// AddDataHandler provides the Data Manager with another DataHandler.
func (dms *DataManagerService) AddDataHandler(handler graph.DataHandler) {
	dms.Handlers = append(dms.Handlers, handler)
}

func (dms *DataManagerService) processRequests() {
	for {
		select {
		case <-dms.PauseChan():
			<-dms.ResumeChan()
		case <-dms.Quit():
			return
		case req := <-dms.DNSRequestChan():
			dms.manageData(req)
		case <-dms.AddrRequestChan():
		case <-dms.ASNRequestChan():
		case <-dms.WhoisRequestChan():
		}
	}
}

func (dms *DataManagerService) manageData(req *requests.DNSRequest) {
	req.Name = strings.ToLower(req.Name)
	req.Domain = strings.ToLower(req.Domain)

	dms.SetActive()
	dms.insertDomain(req.Domain)
	for i, r := range req.Records {
		req.Records[i].Name = strings.ToLower(r.Name)
		req.Records[i].Data = strings.ToLower(r.Data)

		switch uint16(r.Type) {
		case dns.TypeA:
			dms.insertA(req, i)
		case dns.TypeAAAA:
			dms.insertAAAA(req, i)
		case dns.TypeCNAME:
			dms.insertCNAME(req, i)
		case dns.TypePTR:
			dms.insertPTR(req, i)
		case dns.TypeSRV:
			dms.insertSRV(req, i)
		case dns.TypeNS:
			dms.insertNS(req, i)
		case dns.TypeMX:
			dms.insertMX(req, i)
		case dns.TypeTXT:
			dms.insertTXT(req, i)
		case dns.TypeSPF:
			dms.insertSPF(req, i)
		}
	}
}

func (dms *DataManagerService) checkDomain(domain string) bool {
	return dms.domainFilter.Duplicate(domain)
}

func (dms *DataManagerService) insertDomain(domain string) {
	domain = strings.ToLower(domain)
	if domain == "" || dms.checkDomain(domain) {
		return
	}
	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:      dms.Config().UUID.String(),
			Timestamp: time.Now().Format(time.RFC3339),
			Type:      graph.OptDomain,
			Domain:    domain,
			Tag:       requests.DNS,
			Source:    "Forward DNS",
		})
		if err != nil {
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert domain: %v", handler, err))
		}
	}
	dms.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   domain,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertCNAME(req *requests.DNSRequest, recidx int) {
	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}
	domain := strings.ToLower(dms.Pool().SubdomainToDomain(target))
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:         dms.Config().UUID.String(),
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
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert CNAME: %v", handler, err))
		}
	}
	dms.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertA(req *requests.DNSRequest, recidx int) {
	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return
	}
	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:      dms.Config().UUID.String(),
			Timestamp: time.Now().Format(time.RFC3339),
			Type:      graph.OptA,
			Name:      req.Name,
			Domain:    req.Domain,
			Address:   addr,
			Tag:       req.Tag,
			Source:    req.Source,
		})
		if err != nil {
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert A record: %v", handler, err))
		}
	}
	dms.insertInfrastructure(addr)
	if dms.Config().IsDomainInScope(req.Name) {
		dms.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: addr,
			Domain:  req.Domain,
			Tag:     req.Tag,
			Source:  req.Source,
		})
	}
}

func (dms *DataManagerService) insertAAAA(req *requests.DNSRequest, recidx int) {
	addr := strings.TrimSpace(req.Records[recidx].Data)
	if addr == "" {
		return
	}
	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:      dms.Config().UUID.String(),
			Timestamp: time.Now().Format(time.RFC3339),
			Type:      graph.OptAAAA,
			Name:      req.Name,
			Domain:    req.Domain,
			Address:   addr,
			Tag:       req.Tag,
			Source:    req.Source,
		})
		if err != nil {
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert AAAA record: %v", handler, err))
		}
	}
	dms.insertInfrastructure(addr)
	if dms.Config().IsDomainInScope(req.Name) {
		dms.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: addr,
			Domain:  req.Domain,
			Tag:     req.Tag,
			Source:  req.Source,
		})
	}
}

func (dms *DataManagerService) insertPTR(req *requests.DNSRequest, recidx int) {
	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}
	domain := strings.ToLower(dms.Config().WhichDomain(target))
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:       dms.Config().UUID.String(),
			Timestamp:  time.Now().Format(time.RFC3339),
			Type:       graph.OptPTR,
			Name:       req.Name,
			Domain:     domain,
			TargetName: target,
			Tag:        req.Tag,
			Source:     req.Source,
		})
		if err != nil {
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert PTR record: %v", handler, err))
		}
	}
	dms.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
		Name:   target,
		Domain: domain,
		Tag:    requests.DNS,
		Source: req.Source,
	})
}

func (dms *DataManagerService) insertSRV(req *requests.DNSRequest, recidx int) {
	service := resolvers.RemoveLastDot(req.Records[recidx].Name)
	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" || service == "" {
		return
	}

	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:       dms.Config().UUID.String(),
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
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert SRV record: %v", handler, err))
		}
	}

	if domain := dms.Config().WhichDomain(target); domain != "" {
		dms.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    req.Tag,
			Source: req.Source,
		})
	}
}

func (dms *DataManagerService) insertNS(req *requests.DNSRequest, recidx int) {
	pieces := strings.Split(req.Records[recidx].Data, ",")
	target := pieces[len(pieces)-1]
	if target == "" {
		return
	}
	domain := strings.ToLower(dms.Pool().SubdomainToDomain(target))
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:         dms.Config().UUID.String(),
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
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert NS record: %v", handler, err))
		}
	}
	if target != domain {
		dms.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertMX(req *requests.DNSRequest, recidx int) {
	target := resolvers.RemoveLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}
	domain := strings.ToLower(dms.Pool().SubdomainToDomain(target))
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:         dms.Config().UUID.String(),
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
			dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s failed to insert MX record: %v", handler, err))
		}
	}
	if target != domain {
		dms.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   target,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertTXT(req *requests.DNSRequest, recidx int) {
	if !dms.Config().IsDomainInScope(req.Name) {
		return
	}
	dms.findNamesAndAddresses(req.Records[recidx].Data, req.Domain)
}

func (dms *DataManagerService) insertSPF(req *requests.DNSRequest, recidx int) {
	if !dms.Config().IsDomainInScope(req.Name) {
		return
	}
	dms.findNamesAndAddresses(req.Records[recidx].Data, req.Domain)
}

func (dms *DataManagerService) findNamesAndAddresses(data, domain string) {
	ipre := regexp.MustCompile(utils.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		dms.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
			Address: ip,
			Domain:  domain,
			Tag:     requests.DNS,
			Source:  "Forward DNS",
		})
	}

	subre := utils.AnySubdomainRegex()
	for _, name := range subre.FindAllString(data, -1) {
		if !dms.Config().IsDomainInScope(name) {
			continue
		}
		domain := strings.ToLower(dms.Config().WhichDomain(name))
		if domain == "" {
			continue
		}
		dms.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   name,
			Domain: domain,
			Tag:    requests.DNS,
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertInfrastructure(addr string) {
	asn, cidr, desc, err := IPRequest(addr, dms.Bus())
	if err != nil {
		dms.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %v", dms.String(), err))
		return
	}

	for _, handler := range dms.Handlers {
		err := handler.Insert(&graph.DataOptsParams{
			UUID:        dms.Config().UUID.String(),
			Timestamp:   time.Now().Format(time.RFC3339),
			Type:        graph.OptInfrastructure,
			Address:     addr,
			ASN:         asn,
			CIDR:        cidr.String(),
			Description: desc,
		})
		if err != nil {
			dms.Bus().Publish(requests.LogTopic,
				fmt.Sprintf("%s: %s failed to insert infrastructure data: %v", dms.String(), handler, err),
			)
		}
	}
}
