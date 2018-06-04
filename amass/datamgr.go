// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
)

type DataManagerService struct {
	BaseAmassService

	domains map[string]struct{}
	graph   *Graph
	neo4j   *Neo4j
}

func NewDataManagerService(config *AmassConfig) *DataManagerService {
	dms := &DataManagerService{
		domains: make(map[string]struct{}),
		graph:   NewGraph(),
	}

	dms.BaseAmassService = *NewBaseAmassService("Data Manager Service", config, dms)
	return dms
}

func (dms *DataManagerService) OnStart() error {
	var err error

	dms.BaseAmassService.OnStart()

	if dms.Config().Neo4jPath != "" {
		dms.neo4j, err = NewNeo4j(dms.Config().Neo4jPath)
		if err != nil {
			return err
		}
	}

	go dms.processRequests()
	go dms.processOutput()
	return nil
}

func (dms *DataManagerService) OnStop() error {
	dms.BaseAmassService.OnStop()

	if dms.neo4j != nil {
		dms.neo4j.conn.Close()
	}
	return nil
}

func (dms *DataManagerService) processRequests() {
	t := time.NewTicker(dms.Config().Frequency)
	defer t.Stop()

	check := time.NewTicker(10 * time.Second)
	defer check.Stop()
loop:
	for {
		select {
		case <-t.C:
			dms.manageData()
		case <-check.C:
			dms.SetActive(false)
		case <-dms.Quit():
			break loop
		}
	}
}

func (dms *DataManagerService) processOutput() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case <-t.C:
			dms.discoverOutput()
		case <-dms.Quit():
			break loop
		}
	}
	dms.discoverOutput()
}

func (dms *DataManagerService) manageData() {
	req := dms.NextRequest()
	if req == nil {
		return
	}

	dms.SetActive(true)

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

	dms.graph.insertDomain(domain, "dns", "Forward DNS")

	if dms.neo4j != nil {
		dms.neo4j.insertDomain(domain, "dns", "Forward DNS")
	}

	dms.domains[domain] = struct{}{}

	dms.Config().dns.SendRequest(&AmassRequest{
		Name:   domain,
		Domain: domain,
		Tag:    "dns",
		Source: "Forward DNS",
	})

	addrs := LookupIPHistory(domain)
	for _, addr := range addrs {
		_, cidr, _ := IPRequest(addr)
		if cidr != nil {
			dms.AttemptSweep(domain, domain, addr, cidr)
		}
	}
}

func (dms *DataManagerService) insertCNAME(req *AmassRequest, recidx int) {
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	domain := strings.ToLower(dms.Config().dns.SubdomainToDomain(target))

	if target == "" || domain == "" {
		return
	}

	dms.insertDomain(domain)

	dms.graph.insertCNAME(req.Name, req.Domain, target, domain, req.Tag, req.Source)

	if dms.neo4j != nil {
		dms.neo4j.insertCNAME(req.Name, req.Domain, target, domain, req.Tag, req.Source)
	}

	dms.Config().dns.SendRequest(&AmassRequest{
		Name:   target,
		Domain: domain,
		Tag:    "dns",
		Source: "Forward DNS",
	})
}

func (dms *DataManagerService) insertA(req *AmassRequest, recidx int) {
	addr := req.Records[recidx].Data

	if addr == "" {
		return
	}

	dms.graph.insertA(req.Name, req.Domain, addr, req.Tag, req.Source)

	if dms.neo4j != nil {
		dms.neo4j.insertA(req.Name, req.Domain, addr, req.Tag, req.Source)
	}

	dms.insertInfrastructure(addr)

	// Check if active certificate access should be used on this address
	if dms.Config().Active && dms.Config().IsDomainInScope(req.Name) {
		PullCertificate(addr, dms.Config(), false)
	}

	_, cidr, _ := IPRequest(addr)
	if cidr != nil {
		dms.AttemptSweep(req.Name, req.Domain, addr, cidr)
	}
}

func (dms *DataManagerService) insertAAAA(req *AmassRequest, recidx int) {
	addr := req.Records[recidx].Data

	if addr == "" {
		return
	}

	dms.graph.insertAAAA(req.Name, req.Domain, addr, req.Tag, req.Source)

	if dms.neo4j != nil {
		dms.neo4j.insertAAAA(req.Name, req.Domain, addr, req.Tag, req.Source)
	}

	dms.insertInfrastructure(addr)

	// Check if active certificate access should be used on this address
	if dms.Config().Active && dms.Config().IsDomainInScope(req.Name) {
		PullCertificate(addr, dms.Config(), false)
	}

	_, cidr, _ := IPRequest(addr)
	if cidr != nil {
		dms.AttemptSweep(req.Name, req.Domain, addr, cidr)
	}
}

func (dms *DataManagerService) insertPTR(req *AmassRequest, recidx int) {
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	domain := strings.ToLower(dms.Config().dns.SubdomainToDomain(target))

	if target == "" || domain == "" {
		return
	}

	if !dms.Config().IsDomainInScope(domain) {
		return
	}

	dms.insertDomain(domain)

	dms.graph.insertPTR(req.Name, domain, target, req.Tag, req.Source)

	if dms.neo4j != nil {
		dms.neo4j.insertPTR(req.Name, domain, target, req.Tag, req.Source)
	}

	dms.Config().dns.SendRequest(&AmassRequest{
		Name:   target,
		Domain: domain,
		Tag:    "dns",
		Source: "Reverse DNS",
	})
}

func (dms *DataManagerService) insertSRV(req *AmassRequest, recidx int) {
	service := strings.ToLower(removeLastDot(req.Records[recidx].Name))
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))

	if target == "" || service == "" {
		return
	}

	dms.graph.insertSRV(req.Name, req.Domain, service, target, req.Tag, req.Source)

	if dms.neo4j != nil {
		dms.neo4j.insertSRV(req.Name, req.Domain, service, target, req.Tag, req.Source)
	}
}

func (dms *DataManagerService) insertNS(req *AmassRequest, recidx int) {
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	domain := strings.ToLower(dms.Config().dns.SubdomainToDomain(target))

	if target == "" || domain == "" {
		return
	}

	dms.insertDomain(domain)

	dms.graph.insertNS(req.Name, req.Domain, target, domain, req.Tag, req.Source)

	if dms.neo4j != nil {
		dms.neo4j.insertNS(req.Name, req.Domain, target, domain, req.Tag, req.Source)
	}

	if target != domain {
		dms.Config().dns.SendRequest(&AmassRequest{
			Name:   target,
			Domain: domain,
			Tag:    "dns",
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertMX(req *AmassRequest, recidx int) {
	target := strings.ToLower(removeLastDot(req.Records[recidx].Data))
	domain := strings.ToLower(dms.Config().dns.SubdomainToDomain(target))

	if target == "" || domain == "" {
		return
	}

	dms.insertDomain(domain)

	dms.graph.insertMX(req.Name, req.Domain, target, domain, req.Tag, req.Source)

	if dms.neo4j != nil {
		dms.neo4j.insertMX(req.Name, req.Domain, target, domain, req.Tag, req.Source)
	}

	if target != domain {
		dms.Config().dns.SendRequest(&AmassRequest{
			Name:   target,
			Domain: domain,
			Tag:    "dns",
			Source: "Forward DNS",
		})
	}
}

func (dms *DataManagerService) insertInfrastructure(addr string) {
	asn, cidr, desc := IPRequest(addr)
	if asn == 0 {
		return
	}

	dms.graph.insertInfrastructure(addr, asn, cidr, desc)

	if dms.neo4j != nil {
		dms.neo4j.insertInfrastructure(addr, asn, cidr, desc)
	}
}

// AttemptSweep - Initiates a sweep of a subset of the addresses within the CIDR
func (dms *DataManagerService) AttemptSweep(name, domain, addr string, cidr *net.IPNet) {
	if !dms.Config().IsDomainInScope(name) {
		return
	}

	// Get the subset of 200 nearby IP addresses
	ips := CIDRSubset(cidr, addr, 200)
	// Go through the IP addresses
	for _, ip := range ips {
		var ptr string

		if len(ip.To4()) == net.IPv4len {
			ptr = ReverseIP(addr) + ".in-addr.arpa"
		} else if len(ip) == net.IPv6len {
			ptr = IPv6NibbleFormat(hexString(ip)) + ".ip6.arpa"
		} else {
			continue
		}

		dms.Config().dns.SendRequest(&AmassRequest{
			Name:   ptr,
			Domain: domain,
			Tag:    "dns",
			Source: "Reverse DNS",
		})
	}
}

func (dms *DataManagerService) discoverOutput() {
	dms.graph.Lock()
	defer dms.graph.Unlock()

	for key, domain := range dms.graph.Domains {
		output := dms.findSubdomainOutput(domain)

		for _, o := range output {
			o.Domain = key
		}

		go dms.sendOutput(output)
	}
}

func (dms *DataManagerService) findSubdomainOutput(domain *Node) []*AmassOutput {
	var output []*AmassOutput

	if o := dms.buildSubdomainOutput(domain); o != nil {
		output = append(output, o)
	}

	for _, edge := range domain.Edges {
		if edge.Label != "ROOT_OF" {
			continue
		}

		if o := dms.buildSubdomainOutput(edge.To); o != nil {
			output = append(output, o)
		}

		cname := edge.To
		for {
			prev := cname

			for _, e := range cname.Edges {
				if e.Label == "CNAME_TO" {
					cname = e.To
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
func (ds *DNSService) getTypeOfHost(name string) int {
	var qt int

	// If no interesting type has been identified, check for web
	if qt == TypeNorm {

	}
	return qt
}
func (dms *DataManagerService) buildSubdomainOutput(sub *Node) *AmassOutput {
	if _, ok := sub.Properties["sent"]; ok {
		return nil
	}

	output := &AmassOutput{
		Name:   sub.Properties["name"],
		Tag:    sub.Properties["tag"],
		Source: sub.Properties["source"],
	}

	t := TypeNorm
	if st, ok := sub.Properties["type"]; !ok {
		labels := strings.Split(output.Name, ".")

		re := regexp.MustCompile("web|www")
		if re.FindString(labels[0]) != "" {
			t = TypeWeb
		}
	} else {
		if st == "TypeNS" {
			t = TypeNS
		} else if st == "TypeMX" {
			t = TypeMX
		}
	}
	output.Type = t

	cname := dms.traverseCNAME(sub)

	var addrs []*Node
	for _, edge := range cname.Edges {
		if edge.Label == "A_TO" || edge.Label == "AAAA_TO" {
			addrs = append(addrs, edge.To)
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

func (dms *DataManagerService) traverseCNAME(sub *Node) *Node {
	cname := sub
	for {
		prev := cname

		for _, edge := range cname.Edges {
			if edge.Label == "CNAME_TO" {
				cname = edge.To
				break
			}
		}

		if cname == prev {
			break
		}
	}
	return cname
}

func (dms *DataManagerService) obtainInfrastructureData(addr *Node) *AmassAddressInfo {
	infr := &AmassAddressInfo{Address: net.ParseIP(addr.Properties["addr"])}

	var nb *Node
	for _, edge := range addr.Edges {
		if edge.Label == "CONTAINS" {
			nb = edge.From
			break
		}
	}

	if nb == nil {
		return nil
	}
	_, infr.Netblock, _ = net.ParseCIDR(nb.Properties["cidr"])

	var as *Node
	for _, edge := range nb.Edges {
		if edge.Label == "HAS_PREFIX" {
			as = edge.From
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
		if dms.Config().IsDomainInScope(o.Name) {
			dms.Config().Output <- o
		}
	}
}
