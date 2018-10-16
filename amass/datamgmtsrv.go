// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
	"github.com/miekg/dns"
)

type DataManagerService struct {
	core.BaseAmassService

	bus                  evbus.Bus
	Graph                *handlers.Graph
	Handlers             []handlers.DataHandler
	maxDataInputRoutines *utils.Semaphore
	domains              []string
}

func NewDataManagerService(config *core.AmassConfig, bus evbus.Bus) *DataManagerService {
	dms := &DataManagerService{
		bus:                  bus,
		maxDataInputRoutines: utils.NewSemaphore(100),
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
	var paused bool

	for {
		select {
		case <-dms.PauseChan():
			paused = true
		case <-dms.ResumeChan():
			paused = false
		case <-dms.Quit():
			return
		default:
			if paused {
				time.Sleep(time.Second)
				continue
			}
			if req := dms.NextRequest(); req != nil {
				dms.SetActive()
				dms.maxDataInputRoutines.Acquire(1)
				dms.SetActive()
				go dms.manageData(req)
			} else {
				time.Sleep(100 * time.Millisecond)
			}
		}
	}
}

func (dms *DataManagerService) processOutput() {
	t := time.NewTicker(time.Second)
	defer t.Stop()

	for {
		select {
		case <-t.C:
			if out := dms.Graph.GetNewOutput(); len(out) > 0 {
				dms.SetActive()
				go dms.sendOutput(out)
			}
		case <-dms.PauseChan():
			t.Stop()
		case <-dms.ResumeChan():
			t = time.NewTicker(time.Second)
		case <-dms.Quit():
			return
		}
	}
}

func (dms *DataManagerService) sendOutput(output []*core.AmassOutput) {
	for _, o := range output {
		if dms.Config().IsDomainInScope(o.Name) {
			dms.SetActive()
			dms.bus.Publish(core.OUTPUT, o)
		}
	}
}

func (dms *DataManagerService) manageData(req *core.AmassRequest) {
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
	dms.SetActive()
	dms.maxDataInputRoutines.Release(1)
}

func (dms *DataManagerService) checkDomain(domain string) bool {
	dms.Lock()
	dom := dms.domains
	dms.Unlock()

	for _, d := range dom {
		if strings.Compare(d, domain) == 0 {
			return true
		}
	}

	dms.Lock()
	dms.domains = append(dms.domains, domain)
	dms.Unlock()
	return false
}

func (dms *DataManagerService) insertDomain(domain string) {
	if domain == "" || dms.checkDomain(domain) {
		return
	}

	for _, handler := range dms.Handlers {
		if err := handler.InsertDomain(domain, core.DNS, "Forward DNS"); err != nil {
			dms.Config().Log.Printf("%s failed to insert domain: %v", handler, err)
		}
	}

	dms.bus.Publish(core.NEWNAME, &core.AmassRequest{
		Name:   domain,
		Domain: domain,
		Tag:    core.DNS,
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
		err := handler.InsertCNAME(req.Name, req.Domain, target, domain, req.Tag, req.Source)
		if err != nil {
			dms.Config().Log.Printf("%s failed to insert CNAME: %v", handler, err)
		}
	}

	dms.bus.Publish(core.NEWNAME, &core.AmassRequest{
		Name:   target,
		Domain: domain,
		Tag:    core.DNS,
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertA(req *core.AmassRequest, recidx int) {
	addr := req.Records[recidx].Data
	if addr == "" {
		return
	}

	for _, handler := range dms.Handlers {
		if err := handler.InsertA(req.Name, req.Domain, addr, req.Tag, req.Source); err != nil {
			dms.Config().Log.Printf("%s failed to insert A record: %v", handler, err)
		}
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
		if err := handler.InsertAAAA(req.Name, req.Domain, addr, req.Tag, req.Source); err != nil {
			dms.Config().Log.Printf("%s failed to insert AAAA record: %v", handler, err)
		}
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
			dms.bus.Publish(core.NEWNAME, r)
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
		if err := handler.InsertPTR(req.Name, domain, target, req.Tag, req.Source); err != nil {
			dms.Config().Log.Printf("%s failed to insert PTR record: %v", handler, err)
		}
	}

	dms.bus.Publish(core.NEWNAME, &core.AmassRequest{
		Name:   target,
		Domain: domain,
		Tag:    core.DNS,
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
		err := handler.InsertSRV(req.Name, req.Domain, service, target, req.Tag, req.Source)
		if err != nil {
			dms.Config().Log.Printf("%s failed to insert SRV record: %v", handler, err)
		}
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
		err := handler.InsertNS(req.Name, req.Domain, target, domain, req.Tag, req.Source)
		if err != nil {
			dms.Config().Log.Printf("%s failed to insert NS record: %v", handler, err)
		}
	}

	if target != domain {
		dms.bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   target,
			Domain: domain,
			Tag:    core.DNS,
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
		err := handler.InsertMX(req.Name, req.Domain, target, domain, req.Tag, req.Source)
		if err != nil {
			dms.Config().Log.Printf("%s failed to insert MX record: %v", handler, err)
		}
	}

	if target != domain {
		dms.bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   target,
			Domain: domain,
			Tag:    core.DNS,
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
		dms.bus.Publish(core.NEWNAME, &core.AmassRequest{
			Name:   name,
			Domain: req.Domain,
			Tag:    core.DNS,
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
		if err := handler.InsertInfrastructure(addr, asn, cidr, desc); err != nil {
			dms.Config().Log.Printf("%s failed to insert infrastructure data: %v", handler, err)
		}
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
