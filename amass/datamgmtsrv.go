// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	"github.com/miekg/dns"
)

// DataManagerService is the Service that handles all data collected
// within the architecture. This is achieved by watching all the RESOLVED events.
type DataManagerService struct {
	BaseService

	Handlers     []handlers.DataHandler
	filter       *utils.StringFilter
	domainFilter *utils.StringFilter
}

// NewDataManagerService returns he object initialized, but not yet started.
func NewDataManagerService(e *Enumeration) *DataManagerService {
	dms := &DataManagerService{
		filter:       utils.NewStringFilter(),
		domainFilter: utils.NewStringFilter(),
	}

	dms.BaseService = *NewBaseService(e, "Data Manager", dms)
	return dms
}

// OnStart implements the Service interface
func (dms *DataManagerService) OnStart() error {
	dms.BaseService.OnStart()

	dms.Handlers = append(dms.Handlers, dms.Enum().Graph)
	if dms.Enum().DataOptsWriter != nil {
		dms.Handlers = append(dms.Handlers, handlers.NewDataOptsHandler(dms.Enum().DataOptsWriter))
	}

	go dms.processRequests()
	return nil
}

func (dms *DataManagerService) processRequests() {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-dms.PauseChan():
			<-dms.ResumeChan()
		case <-dms.Quit():
			return
		case <-t.C:
			dms.sendOutput()
		case req := <-dms.RequestChan():
			go dms.manageData(req)
		}
	}
}

func (dms *DataManagerService) sendOutput() {
	if out := dms.Enum().Graph.GetNewOutput(); len(out) > 0 {
		for _, o := range out {
			if !dms.filter.Duplicate(o.Name) && dms.Enum().Config.IsDomainInScope(o.Name) {
				go dms.Enum().OutputEvent(o)
			}
		}
	}
}

func (dms *DataManagerService) manageData(req *Request) {
	req.Name = strings.ToLower(req.Name)
	req.Domain = strings.ToLower(req.Domain)

	dms.SetActive()
	dms.insertDomain(req.Domain)
	for i, r := range req.Records {
		r.Name = strings.ToLower(r.Name)
		r.Data = strings.ToLower(r.Data)

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
		dms.SetActive()
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
		if err := handler.InsertDomain(domain, DNS, "Forward DNS"); err != nil {
			dms.Enum().Log.Printf("%s failed to insert domain: %v", handler, err)
		}
	}
	dms.Enum().NewNameEvent(&Request{
		Name:   domain,
		Domain: domain,
		Tag:    DNS,
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertCNAME(req *Request, recidx int) {
	target := removeLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}
	domain := SubdomainToDomain(target)
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		err := handler.InsertCNAME(req.Name, req.Domain, target, domain, req.Tag, req.Source)
		if err != nil {
			dms.Enum().Log.Printf("%s failed to insert CNAME: %v", handler, err)
		}
	}
	dms.Enum().NewNameEvent(&Request{
		Name:   target,
		Domain: domain,
		Tag:    DNS,
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertA(req *Request, recidx int) {
	addr := req.Records[recidx].Data
	if addr == "" {
		return
	}
	for _, handler := range dms.Handlers {
		if err := handler.InsertA(req.Name, req.Domain, addr, req.Tag, req.Source); err != nil {
			dms.Enum().Log.Printf("%s failed to insert A record: %v", handler, err)
		}
	}
	dms.insertInfrastructure(addr)
	if dms.Enum().Config.IsDomainInScope(req.Name) {
		dms.Enum().NewAddressEvent(&Request{
			Domain:  req.Domain,
			Address: addr,
			Tag:     req.Tag,
			Source:  req.Source,
		})
	}
}

func (dms *DataManagerService) insertAAAA(req *Request, recidx int) {
	addr := req.Records[recidx].Data
	if addr == "" {
		return
	}
	for _, handler := range dms.Handlers {
		if err := handler.InsertAAAA(req.Name, req.Domain, addr, req.Tag, req.Source); err != nil {
			dms.Enum().Log.Printf("%s failed to insert AAAA record: %v", handler, err)
		}
	}
	dms.insertInfrastructure(addr)
	if dms.Enum().Config.IsDomainInScope(req.Name) {
		dms.Enum().NewAddressEvent(&Request{
			Domain:  req.Domain,
			Address: addr,
			Tag:     req.Tag,
			Source:  req.Source,
		})
	}
}

func (dms *DataManagerService) insertPTR(req *Request, recidx int) {
	target := removeLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}
	domain := dms.Enum().Config.WhichDomain(target)
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		if err := handler.InsertPTR(req.Name, domain, target, req.Tag, req.Source); err != nil {
			dms.Enum().Log.Printf("%s failed to insert PTR record: %v", handler, err)
		}
	}
	dms.Enum().NewNameEvent(&Request{
		Name:   target,
		Domain: domain,
		Tag:    DNS,
		Source: req.Source,
	})
}

func (dms *DataManagerService) insertSRV(req *Request, recidx int) {
	service := removeLastDot(req.Records[recidx].Name)
	target := removeLastDot(req.Records[recidx].Data)
	if target == "" || service == "" {
		return
	}

	for _, handler := range dms.Handlers {
		err := handler.InsertSRV(req.Name, req.Domain, service, target, req.Tag, req.Source)
		if err != nil {
			dms.Enum().Log.Printf("%s failed to insert SRV record: %v", handler, err)
		}
	}
}

func (dms *DataManagerService) insertNS(req *Request, recidx int) {
	pieces := strings.Split(req.Records[recidx].Data, ",")
	target := pieces[len(pieces)-1]
	if target == "" {
		return
	}
	domain := SubdomainToDomain(target)
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		err := handler.InsertNS(req.Name, req.Domain, target, domain, req.Tag, req.Source)
		if err != nil {
			dms.Enum().Log.Printf("%s failed to insert NS record: %v", handler, err)
		}
	}
	if target != domain {
		dms.Enum().NewNameEvent(&Request{
			Name:   target,
			Domain: domain,
			Tag:    DNS,
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertMX(req *Request, recidx int) {
	target := removeLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}
	domain := SubdomainToDomain(target)
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		err := handler.InsertMX(req.Name, req.Domain, target, domain, req.Tag, req.Source)
		if err != nil {
			dms.Enum().Log.Printf("%s failed to insert MX record: %v", handler, err)
		}
	}
	if target != domain {
		dms.Enum().NewNameEvent(&Request{
			Name:   target,
			Domain: domain,
			Tag:    DNS,
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertTXT(req *Request, recidx int) {
	if !dms.Enum().Config.IsDomainInScope(req.Name) {
		return
	}
	dms.findNamesAndAddresses(req.Records[recidx].Data)
}

func (dms *DataManagerService) insertSPF(req *Request, recidx int) {
	if !dms.Enum().Config.IsDomainInScope(req.Name) {
		return
	}
	dms.findNamesAndAddresses(req.Records[recidx].Data)
}

func (dms *DataManagerService) findNamesAndAddresses(data string) {
	ipre := regexp.MustCompile(utils.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		dms.Enum().NewAddressEvent(&Request{
			Address: ip,
			Tag:     DNS,
			Source:  "Forward DNS",
		})
	}

	subre := utils.AnySubdomainRegex()
	for _, name := range subre.FindAllString(data, -1) {
		if !dms.Enum().Config.IsDomainInScope(name) {
			continue
		}
		domain := dms.Enum().Config.WhichDomain(name)
		if domain == "" {
			continue
		}
		dms.Enum().NewNameEvent(&Request{
			Name:   name,
			Domain: domain,
			Tag:    DNS,
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertInfrastructure(addr string) {
	asn, cidr, desc, err := IPRequest(addr)
	if err != nil {
		dms.Enum().Log.Printf("%v", err)
		return
	}

	for _, handler := range dms.Handlers {
		if err := handler.InsertInfrastructure(addr, asn, cidr, desc); err != nil {
			dms.Enum().Log.Printf("%s failed to insert infrastructure data: %v", handler, err)
		}
	}
}

func removeLastDot(name string) string {
	sz := len(name)
	if sz > 0 && name[sz-1] == '.' {
		return name[:sz-1]
	}
	return name
}
