// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	evbus "github.com/asaskevich/EventBus"
	"github.com/miekg/dns"
)

type DataManagerService struct {
	core.BaseAmassService

	bus      evbus.Bus
	Graph    *handlers.Graph
	Handlers []handlers.DataHandler
	domains  map[string]struct{}
}

func NewDataManagerService(config *core.AmassConfig, bus evbus.Bus) *DataManagerService {
	dms := &DataManagerService{
		bus:     bus,
		domains: make(map[string]struct{}),
	}

	dms.BaseAmassService = *core.NewBaseAmassService("Data Manager Service", config, dms)
	return dms
}

func (dms *DataManagerService) OnStart() error {
	dms.BaseAmassService.OnStart()

	dms.bus.SubscribeAsync(core.RESOLVED, dms.SendRequest, false)

	dms.Graph = handlers.NewGraph()
	dms.Handlers = append(dms.Handlers, dms.Graph)
	if dms.Config().DataOptsWriter != nil {
		dms.Handlers = append(dms.Handlers, handlers.NewDataOptsHandler(dms.Config().DataOptsWriter))
	}
	go dms.processRequests()
	go dms.processOutput()
	return nil
}

func (dms *DataManagerService) OnPause() error {
	return nil
}

func (dms *DataManagerService) OnResume() error {
	return nil
}

func (dms *DataManagerService) OnStop() error {
	dms.BaseAmassService.OnStop()

	dms.bus.Unsubscribe(core.RESOLVED, dms.SendRequest)
	return nil
}

func (dms *DataManagerService) processRequests() {
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if req := dms.NextRequest(); req != nil {
				dms.manageData(req)
			}
		case <-dms.PauseChan():
			t.Stop()
		case <-dms.ResumeChan():
			t = time.NewTicker(500 * time.Millisecond)
		case <-dms.Quit():
			return
		}
	}
}

func (dms *DataManagerService) processOutput() {
	t := time.NewTicker(time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			dms.sendOutput(dms.Graph.GetNewOutput())
		case <-dms.PauseChan():
			t.Stop()
		case <-dms.ResumeChan():
			t = time.NewTicker(time.Second)
		case <-dms.Quit():
			break loop
		}
	}
	dms.sendOutput(dms.Graph.GetNewOutput())
}

func (dms *DataManagerService) sendOutput(output []*core.AmassOutput) {
	for _, o := range output {
		dms.SetActive()
		if dms.Config().IsDomainInScope(o.Name) {
			dms.bus.Publish(core.OUTPUT, o)
		}
	}
}

func (dms *DataManagerService) manageData(req *core.AmassRequest) {
	dms.SetActive()
	req.Name = strings.ToLower(req.Name)
	req.Domain = strings.ToLower(req.Domain)

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
		}
	}
}

func (dms *DataManagerService) insertDomain(domain string) {
	if domain == "" {
		return
	}

	if _, ok := dms.domains[domain]; ok {
		return
	}
	dms.domains[domain] = struct{}{}

	for _, handler := range dms.Handlers {
		handler.InsertDomain(domain, "dns", "Forward DNS")
	}

	dms.bus.Publish(core.DNSQUERY, &core.AmassRequest{
		Name:   domain,
		Domain: domain,
		Tag:    "dns",
		Source: "Forward DNS",
	})

	addrs, err := LookupIPHistory(domain)
	if err != nil {
		dms.Config().Log.Printf("LookupIPHistory error: %v", err)
		return
	}

	for _, addr := range addrs {
		if _, cidr, _, err := IPRequest(addr); err == nil {
			dms.AttemptSweep(domain, addr, cidr)
		} else {
			dms.Config().Log.Printf("%v", err)
		}
	}
}

func (dms *DataManagerService) insertCNAME(req *core.AmassRequest, recidx int) {
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	domain := strings.ToLower(SubdomainToDomain(target))
	if target == "" || domain == "" {
		return
	}

	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		handler.InsertCNAME(req.Name, req.Domain, target, domain, req.Tag, req.Source)
	}

	dms.bus.Publish(core.DNSQUERY, &core.AmassRequest{
		Name:   target,
		Domain: domain,
		Tag:    "dns",
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertA(req *core.AmassRequest, recidx int) {
	addr := req.Records[recidx].Data
	if addr == "" {
		return
	}

	for _, handler := range dms.Handlers {
		handler.InsertA(req.Name, req.Domain, addr, req.Tag, req.Source)
	}

	dms.insertInfrastructure(addr)
	// Check if active certificate access should be used on this address
	if dms.Config().Active && dms.Config().IsDomainInScope(req.Name) {
		dms.obtainNamesFromCertificate(addr)
	}

	if _, cidr, _, err := IPRequest(addr); err == nil {
		dms.AttemptSweep(req.Domain, addr, cidr)
	} else {
		dms.Config().Log.Printf("%v", err)
	}
}

func (dms *DataManagerService) insertAAAA(req *core.AmassRequest, recidx int) {
	addr := req.Records[recidx].Data
	if addr == "" {
		return
	}

	for _, handler := range dms.Handlers {
		handler.InsertAAAA(req.Name, req.Domain, addr, req.Tag, req.Source)
	}

	dms.insertInfrastructure(addr)
	// Check if active certificate access should be used on this address
	if dms.Config().Active && dms.Config().IsDomainInScope(req.Name) {
		dms.obtainNamesFromCertificate(addr)
	}

	if _, cidr, _, err := IPRequest(addr); err == nil {
		dms.AttemptSweep(req.Domain, addr, cidr)
	} else {
		dms.Config().Log.Printf("%v", err)
	}
}

func (dms *DataManagerService) obtainNamesFromCertificate(addr string) {
	for _, r := range PullCertificateNames(addr, dms.Config().Ports) {
		if dms.Config().IsDomainInScope(r.Domain) {
			dms.bus.Publish(core.DNSQUERY, r)
		}
	}
}

func (dms *DataManagerService) insertPTR(req *core.AmassRequest, recidx int) {
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	domain := strings.ToLower(SubdomainToDomain(target))
	if target == "" || domain == "" || !dms.Config().IsDomainInScope(domain) {
		return
	}

	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		handler.InsertPTR(req.Name, domain, target, req.Tag, req.Source)
	}

	dms.bus.Publish(core.DNSQUERY, &core.AmassRequest{
		Name:   target,
		Domain: domain,
		Tag:    "dns",
		Source: "Reverse DNS",
	})
}

func (dms *DataManagerService) insertSRV(req *core.AmassRequest, recidx int) {
	service := strings.ToLower(removeLastDot(req.Records[recidx].Name))
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	if target == "" || service == "" {
		return
	}

	for _, handler := range dms.Handlers {
		handler.InsertSRV(req.Name, req.Domain, service, target, req.Tag, req.Source)
	}
}

func (dms *DataManagerService) insertNS(req *core.AmassRequest, recidx int) {
	pieces := strings.Split(req.Records[recidx].Data, ",")
	target := strings.ToLower(pieces[len(pieces)-1])
	domain := strings.ToLower(SubdomainToDomain(target))
	if target == "" || domain == "" {
		return
	}

	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		handler.InsertNS(req.Name, req.Domain, target, domain, req.Tag, req.Source)
	}

	if target != domain {
		dms.bus.Publish(core.DNSQUERY, &core.AmassRequest{
			Name:   target,
			Domain: domain,
			Tag:    "dns",
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertMX(req *core.AmassRequest, recidx int) {
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	domain := strings.ToLower(SubdomainToDomain(target))
	if target == "" || domain == "" {
		return
	}

	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		handler.InsertMX(req.Name, req.Domain, target, domain, req.Tag, req.Source)
	}

	if target != domain {
		dms.bus.Publish(core.DNSQUERY, &core.AmassRequest{
			Name:   target,
			Domain: domain,
			Tag:    "dns",
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertTXT(req *core.AmassRequest, recidx int) {
	if !dms.Config().IsDomainInScope(req.Name) {
		return
	}
	re := dms.Config().DomainRegex(req.Domain)
	if re == nil {
		return
	}
	txt := req.Records[recidx].Data
	for _, name := range re.FindAllString(txt, -1) {
		dms.bus.Publish(core.DNSQUERY, &core.AmassRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    "dns",
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertInfrastructure(addr string) {
	asn, cidr, desc, err := IPRequest(addr)
	if err != nil {
		dms.Config().Log.Printf("%v", err)
		return
	}

	for _, handler := range dms.Handlers {
		handler.InsertInfrastructure(addr, asn, cidr, desc)
	}
}

// AttemptSweep - Initiates a sweep of a subset of the addresses within the CIDR
func (dms *DataManagerService) AttemptSweep(domain, addr string, cidr *net.IPNet) {
	if !dms.Config().IsDomainInScope(domain) {
		return
	}

	dms.bus.Publish(core.DNSSWEEP, domain, addr, cidr)
}

func removeLastDot(name string) string {
	sz := len(name)

	if sz > 0 && name[sz-1] == '.' {
		return name[:sz-1]
	}
	return name
}
