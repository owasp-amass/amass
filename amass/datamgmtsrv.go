// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/handlers"
	evbus "github.com/asaskevich/EventBus"
	"github.com/miekg/dns"
)

var (
	WebRegex *regexp.Regexp = regexp.MustCompile("web|www")
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
	t := time.NewTicker(dms.Config().Frequency)
loop:
	for {
		select {
		case <-t.C:
			dms.manageData()
		case <-dms.PauseChan():
			t.Stop()
		case <-dms.ResumeChan():
			t = time.NewTicker(dms.Config().Frequency)
		case <-dms.Quit():
			break loop
		}
	}
	t.Stop()
}

func (dms *DataManagerService) processOutput() {
	t := time.NewTicker(2 * time.Second)
loop:
	for {
		select {
		case <-t.C:
			if dms.NumOfRequests() < 100 {
				dms.discoverOutput()
			}
		case <-dms.PauseChan():
			t.Stop()
		case <-dms.ResumeChan():
			t = time.NewTicker(dms.Config().Frequency)
		case <-dms.Quit():
			break loop
		}
	}
	t.Stop()
	dms.discoverOutput()
}

func (dms *DataManagerService) manageData() {
	req := dms.NextRequest()
	if req == nil {
		return
	}

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
		for _, domain := range dms.Config().Domains() {
			if r.Domain == domain {
				dms.bus.Publish(core.DNSQUERY, r)
				break
			}
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

func (dms *DataManagerService) discoverOutput() {
	dms.Graph.Lock()
	defer dms.Graph.Unlock()

	for key, domain := range dms.Graph.Domains {
		output := dms.findSubdomainOutput(domain)

		for _, o := range output {
			o.Domain = key
		}

		go dms.sendOutput(output)
	}
}

func (dms *DataManagerService) findSubdomainOutput(domain *handlers.Node) []*AmassOutput {
	var output []*AmassOutput

	if o := dms.buildSubdomainOutput(domain); o != nil {
		output = append(output, o)
	}

	for _, idx := range domain.Edges {
		edge := dms.Graph.Edges[idx]
		if edge.Label != "ROOT_OF" {
			continue
		}

		n := dms.Graph.Nodes[edge.To]
		if o := dms.buildSubdomainOutput(n); o != nil {
			output = append(output, o)
		}

		cname := n
		for {
			prev := cname

			for _, i := range cname.Edges {
				e := dms.Graph.Edges[i]
				if e.Label == "CNAME_TO" {
					cname = dms.Graph.Nodes[e.To]
					break
				}
			}

			if cname == prev {
				break
			}

			if o := dms.buildSubdomainOutput(cname); o != nil {
				output = append(output, o)
			}
		}
	}
	return output
}

func (dms *DataManagerService) buildSubdomainOutput(sub *handlers.Node) *AmassOutput {
	if _, ok := sub.Properties["sent"]; ok {
		return nil
	}

	output := &AmassOutput{
		Name:   sub.Properties["name"],
		Tag:    sub.Properties["tag"],
		Source: sub.Properties["source"],
	}

	t := core.TypeNorm
	if sub.Labels[0] != "NS" && sub.Labels[0] != "MX" {
		labels := strings.Split(output.Name, ".")

		if WebRegex.FindString(labels[0]) != "" {
			t = core.TypeWeb
		}
	} else {
		if sub.Labels[0] == "NS" {
			t = core.TypeNS
		} else if sub.Labels[0] == "MX" {
			t = core.TypeMX
		}
	}
	output.Type = t

	cname := dms.traverseCNAME(sub)

	var addrs []*handlers.Node
	for _, idx := range cname.Edges {
		edge := dms.Graph.Edges[idx]
		if edge.Label == "A_TO" || edge.Label == "AAAA_TO" {
			n := dms.Graph.Nodes[edge.To]

			addrs = append(addrs, n)
		}
	}

	if len(addrs) == 0 {
		return nil
	}

	for _, addr := range addrs {
		if i := dms.obtainInfrastructureData(addr); i != nil {
			output.Addresses = append(output.Addresses, *i)
		}
	}

	if len(output.Addresses) == 0 {
		return nil
	}

	sub.Properties["sent"] = "yes"
	return output
}

func (dms *DataManagerService) traverseCNAME(sub *handlers.Node) *handlers.Node {
	cname := sub
	for {
		prev := cname
		for _, idx := range cname.Edges {
			edge := dms.Graph.Edges[idx]
			if edge.Label == "CNAME_TO" {
				cname = dms.Graph.Nodes[edge.To]
				break
			}
		}

		if cname == prev {
			break
		}
	}
	return cname
}

func (dms *DataManagerService) obtainInfrastructureData(addr *handlers.Node) *AmassAddressInfo {
	infr := &AmassAddressInfo{Address: net.ParseIP(addr.Properties["addr"])}

	var nb *handlers.Node
	for _, idx := range addr.Edges {
		edge := dms.Graph.Edges[idx]
		if edge.Label == "CONTAINS" {
			nb = dms.Graph.Nodes[edge.From]
			break
		}
	}

	if nb == nil {
		return nil
	}
	_, infr.Netblock, _ = net.ParseCIDR(nb.Properties["cidr"])

	var as *handlers.Node
	for _, idx := range nb.Edges {
		edge := dms.Graph.Edges[idx]
		if edge.Label == "HAS_PREFIX" {
			as = dms.Graph.Nodes[edge.From]
			break
		}
	}

	if as == nil {
		return nil
	}

	infr.ASN, _ = strconv.Atoi(as.Properties["asn"])
	infr.Description = as.Properties["desc"]
	return infr
}

func (dms *DataManagerService) sendOutput(output []*AmassOutput) {
	for _, o := range output {
		dms.SetActive()
		if dms.Config().IsDomainInScope(o.Name) {
			dms.bus.Publish(core.OUTPUT, o)
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
