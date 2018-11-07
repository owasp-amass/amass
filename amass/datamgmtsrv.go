// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
	"github.com/miekg/dns"
)

// DataManagerService is the AmassService that handles all data collected
// within the architecture. This is achieved by watching all the RESOLVED events.
type DataManagerService struct {
	core.BaseAmassService

	bus      evbus.Bus
	Handlers []handlers.DataHandler
	domains  []string
}

// NewDataManagerService requires the enumeration configuration and event bus as parameters.
// The object returned is initialized, but has not yet been started.
func NewDataManagerService(config *core.AmassConfig, bus evbus.Bus) *DataManagerService {
	dms := &DataManagerService{bus: bus}

	dms.BaseAmassService = *core.NewBaseAmassService("Data Manager Service", config, dms)
	return dms
}

// OnStart implements the AmassService interface
func (dms *DataManagerService) OnStart() error {
	dms.BaseAmassService.OnStart()

	dms.bus.SubscribeAsync(core.CHECKED, dms.SendRequest, false)

	dms.Handlers = append(dms.Handlers, dms.Config().Graph())
	if dms.Config().DataOptsWriter != nil {
		dms.Handlers = append(dms.Handlers, handlers.NewDataOptsHandler(dms.Config().DataOptsWriter))
	}
	go dms.processRequests()
	go dms.processOutput()
	return nil
}

// OnPause implements the AmassService interface
func (dms *DataManagerService) OnPause() error {
	return nil
}

// OnResume implements the AmassService interface
func (dms *DataManagerService) OnResume() error {
	return nil
}

// OnStop implements the AmassService interface
func (dms *DataManagerService) OnStop() error {
	dms.BaseAmassService.OnStop()

	dms.bus.Unsubscribe(core.CHECKED, dms.SendRequest)
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
				dms.manageData(req)
			} else {
				time.Sleep(10 * time.Millisecond)
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
			if out := dms.Config().Graph().GetNewOutput(); len(out) > 0 {
				dms.sendOutput(out)
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
	dms.SetActive()
	for _, o := range output {
		if dms.Config().IsDomainInScope(o.Name) {
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
		case dns.TypeSPF:
			dms.insertSPF(req, i)
		}
	}
}

func (dms *DataManagerService) publishRequest(req *core.AmassRequest) {
	dms.Config().MaxFlow.Acquire(1)
	dms.bus.Publish(core.NEWNAME, req)
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
	domain = strings.ToLower(domain)
	if domain == "" || dms.checkDomain(domain) {
		return
	}
	for _, handler := range dms.Handlers {
		if err := handler.InsertDomain(domain, core.DNS, "Forward DNS"); err != nil {
			dms.Config().Log.Printf("%s failed to insert domain: %v", handler, err)
		}
	}
	go dms.publishRequest(&core.AmassRequest{
		Name:   domain,
		Domain: domain,
		Tag:    core.DNS,
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertCNAME(req *core.AmassRequest, recidx int) {
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
			dms.Config().Log.Printf("%s failed to insert CNAME: %v", handler, err)
		}
	}
	go dms.publishRequest(&core.AmassRequest{
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
		dms.bus.Publish(core.ACTIVECERT, addr)
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
		dms.bus.Publish(core.ACTIVECERT, addr)
	}
}

func (dms *DataManagerService) insertPTR(req *core.AmassRequest, recidx int) {
	target := removeLastDot(req.Records[recidx].Data)
	if target == "" {
		return
	}
	domain := dms.Config().WhichDomain(target)
	if domain == "" {
		return
	}
	dms.insertDomain(domain)
	for _, handler := range dms.Handlers {
		if err := handler.InsertPTR(req.Name, domain, target, req.Tag, req.Source); err != nil {
			dms.Config().Log.Printf("%s failed to insert PTR record: %v", handler, err)
		}
	}
	go dms.publishRequest(&core.AmassRequest{
		Name:   target,
		Domain: domain,
		Tag:    core.DNS,
		Source: "Reverse DNS",
	})
}

func (dms *DataManagerService) insertSRV(req *core.AmassRequest, recidx int) {
	service := removeLastDot(req.Records[recidx].Name)
	target := removeLastDot(req.Records[recidx].Data)
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
			dms.Config().Log.Printf("%s failed to insert NS record: %v", handler, err)
		}
	}
	if target != domain {
		go dms.publishRequest(&core.AmassRequest{
			Name:   target,
			Domain: domain,
			Tag:    core.DNS,
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertMX(req *core.AmassRequest, recidx int) {
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
			dms.Config().Log.Printf("%s failed to insert MX record: %v", handler, err)
		}
	}
	if target != domain {
		go dms.publishRequest(&core.AmassRequest{
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
	dms.findNamesAndAddresses(req.Records[recidx].Data)
}

func (dms *DataManagerService) insertSPF(req *core.AmassRequest, recidx int) {
	if !dms.Config().IsDomainInScope(req.Name) {
		return
	}
	dms.findNamesAndAddresses(req.Records[recidx].Data)
}

func (dms *DataManagerService) findNamesAndAddresses(data string) {
	ipre := regexp.MustCompile(utils.IPv4RE)
	for _, ip := range ipre.FindAllString(data, -1) {
		if _, cidr, _, err := IPRequest(ip); err == nil {
			dms.bus.Publish(core.DNSSWEEP, ip, cidr)
		} else {
			dms.Config().Log.Printf("%v", err)
		}
	}
	subre := utils.AnySubdomainRegex()
	for _, name := range subre.FindAllString(data, -1) {
		if !dms.Config().IsDomainInScope(name) {
			continue
		}
		domain := dms.Config().WhichDomain(name)
		if domain == "" {
			continue
		}
		go dms.publishRequest(&core.AmassRequest{
			Name:   name,
			Domain: domain,
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

	// Request the reverse DNS sweep for the addr
	dms.bus.Publish(core.DNSSWEEP, addr, cidr)

	for _, handler := range dms.Handlers {
		if err := handler.InsertInfrastructure(addr, asn, cidr, desc); err != nil {
			dms.Config().Log.Printf("%s failed to insert infrastructure data: %v", handler, err)
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
