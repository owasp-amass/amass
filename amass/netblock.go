// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

type cacheRequest struct {
	Req  *AmassRequest
	Type string
	Resp chan *AmassRequest
}

type ASRecord struct {
	ASN            int
	Prefix         string
	CC             string
	Registry       string
	AllocationDate time.Time
	Description    string
	Netblocks      []string
}

type NetblockService struct {
	BaseAmassService

	// Caches the data collected from online sources
	cache map[int]*ASRecord

	// Data cache requests are sent here
	requests chan *cacheRequest
}

func NewNetblockService(in, out chan *AmassRequest, config *AmassConfig) *NetblockService {
	ns := &NetblockService{
		cache:    make(map[int]*ASRecord),
		requests: make(chan *cacheRequest, 50),
	}

	ns.BaseAmassService = *NewBaseAmassService("Netblock Service", config, ns)

	ns.input = in
	ns.output = out
	return ns
}

func (ns *NetblockService) OnStart() error {
	ns.BaseAmassService.OnStart()

	go ns.cacheManager()
	go ns.processRequests()
	go ns.initialRequests()
	return nil
}

func (ns *NetblockService) OnStop() error {
	ns.BaseAmassService.OnStop()
	return nil
}

func (ns *NetblockService) initialRequests() {
	// Do root domain names need to be discovered?
	if !ns.Config().AdditionalDomains {
		return
	}
	// Enter all ASN requests into the queue
	for _, asn := range ns.Config().ASNs {
		ns.performLookup(&AmassRequest{
			ASN:        asn,
			addDomains: true,
		})
	}
	// Enter all CIDR requests into the queue
	for _, cidr := range ns.Config().CIDRs {
		ns.performLookup(&AmassRequest{
			Netblock:   cidr,
			addDomains: true,
		})
	}
	// Enter all IP address requests from ranges
	for _, rng := range ns.Config().Ranges {
		ips := RangeHosts(rng)

		for _, ip := range ips {
			ns.performLookup(&AmassRequest{
				Address:    ip,
				addDomains: true,
			})
		}
	}
	// Enter all IP address requests into the queue
	for _, ip := range ns.Config().IPs {
		ns.performLookup(&AmassRequest{
			Address:    ip.String(),
			addDomains: true,
		})
	}
}

func (ns *NetblockService) processRequests() {
	t := time.NewTicker(10 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ns.Input():
			go ns.performLookup(req)
		case <-t.C:
			ns.SetActive(false)
		case <-ns.Quit():
			break loop
		}
	}
}

func (ns *NetblockService) performLookup(req *AmassRequest) {
	ns.SetActive(true)

	var rt string
	// Which type of lookup will be performed?
	if req.Address != "" {
		rt = "IP"
	} else if req.Netblock != nil {
		rt = "CIDR"
	} else if req.ASN != 0 {
		rt = "ASN"
	}

	response := make(chan *AmassRequest, 2)

	ns.requests <- &cacheRequest{
		Req:  req,
		Type: rt,
		Resp: response,
	}
	ns.sendRequest(<-response)
}

func (ns *NetblockService) sendRequest(req *AmassRequest) {
	var required, pass bool

	if req == nil {
		return
	}

	// Check if this request should be stopped due to infrastructure contraints
	if len(ns.Config().ASNs) > 0 {
		required = true
		for _, asn := range ns.Config().ASNs {
			if asn == req.ASN {
				pass = true
				break
			}
		}
	}
	if !pass && len(ns.Config().CIDRs) > 0 {
		required = true
		for _, cidr := range ns.Config().CIDRs {
			if cidr.String() == req.Netblock.String() {
				pass = true
				break
			}
		}
	}
	if !pass && len(ns.Config().Ranges) > 0 {
		required = true
		for _, rng := range ns.Config().Ranges {
			ips := RangeHosts(rng)
			for _, ip := range ips {
				if ip == req.Address {
					pass = true
					break
				}
			}
			if pass {
				break
			}
		}
	}
	if !pass && len(ns.Config().IPs) > 0 {
		required = true
		for _, ip := range ns.Config().IPs {
			if ip.String() == req.Address {
				pass = true
				break
			}
		}
	}
	if required && !pass {
		return
	}
	// Send it on it's way
	ns.SendOut(req)
}

// cacheManager - Goroutine that handles all requests and updates on the data cache
func (ns *NetblockService) cacheManager() {
loop:
	for {
		select {
		case cr := <-ns.requests:
			switch cr.Type {
			case "IP":
				ns.IPRequest(cr)
			case "CIDR":
				ns.CIDRRequest(cr)
			case "ASN":
				ns.ASNRequest(cr)
			}
		case <-ns.Quit():
			break loop
		}
	}
}

func (ns *NetblockService) IPRequest(r *cacheRequest) {
	// Is the data already available in the cache?
	r.Req.ASN, r.Req.Netblock, r.Req.ISP = ns.ipSearch(r.Req.Address)
	if r.Req.ASN != 0 {
		// Return the cached data
		r.Resp <- r.Req
		return
	}
	// Need to pull the online data
	record := ns.FetchOnlineData(r.Req.Address, 0)
	if record == nil {
		r.Resp <- nil
		return
	}
	// Add it to the cache
	ns.cache[record.ASN] = record
	// Lets try again
	r.Req.ASN, r.Req.Netblock, r.Req.ISP = ns.ipSearch(r.Req.Address)
	if r.Req.ASN == 0 {
		r.Resp <- nil
		return
	}
	r.Resp <- r.Req
}

func (ns *NetblockService) ipSearch(addr string) (int, *net.IPNet, string) {
	var a int
	var cidr *net.IPNet
	var desc string

	ip := net.ParseIP(addr)
loop:
	// Check that the necessary data is already cached
	for asn, record := range ns.cache {
		for _, netblock := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(netblock)
			if err != nil {
				continue
			}

			if ipnet.Contains(ip) {
				a = asn
				cidr = ipnet
				desc = record.Description
				break loop
			}
		}
	}
	return a, cidr, desc
}

func (ns *NetblockService) CIDRRequest(r *cacheRequest) {
	r.Req.ASN, r.Req.ISP = ns.cidrSearch(r.Req.Netblock)
	// Does the data need to be obtained?
	if r.Req.ASN != 0 {
		r.Resp <- r.Req
		return
	}
	// Need to pull the online data
	record := ns.FetchOnlineData(r.Req.Netblock.IP.String(), 0)
	if record == nil {
		r.Resp <- nil
		return
	}
	// Add it to the cache
	ns.cache[record.ASN] = record
	// Lets try again
	r.Req.ASN, r.Req.ISP = ns.cidrSearch(r.Req.Netblock)
	if r.Req.ASN == 0 {
		r.Resp <- nil
		return
	}
	r.Resp <- r.Req
}

func (ns *NetblockService) cidrSearch(ipnet *net.IPNet) (int, string) {
	var a int
	var cidr *net.IPNet
	var desc string
loop:
	// Check that the necessary data is already cached
	for asn, record := range ns.cache {
		for _, netblock := range record.Netblocks {
			if netblock == cidr.String() {
				a = asn
				cidr = ipnet
				desc = record.Description
				break loop
			}
		}
	}
	return a, desc
}

func (ns *NetblockService) ASNRequest(r *cacheRequest) {
	var record *ASRecord
	// Does the data need to be obtained?
	if _, found := ns.cache[r.Req.ASN]; !found {
		record = ns.FetchOnlineData("", r.Req.ASN)
		if record == nil {
			r.Resp <- nil
			return
		}
		// Insert the AS record into the cache
		ns.cache[record.ASN] = record
	}
	// For every netblock, initiate subdomain name discovery
	for _, cidr := range record.Netblocks {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		// Send the request for this netblock
		ns.sendRequest(&AmassRequest{
			ASN:        record.ASN,
			Netblock:   ipnet,
			ISP:        record.Description,
			addDomains: r.Req.addDomains,
		})
	}
}

func (ns *NetblockService) FetchOnlineData(addr string, asn int) *ASRecord {
	if addr == "" && asn == 0 {
		return nil
	}

	var cidr string
	// If the ASN was not provided, look it up
	if asn == 0 {
		asn, cidr = ns.originLookup(addr)
		if asn == 0 {
			return nil
		}
	}
	// Get the ASN record from the online source
	record := ns.asnLookup(asn)
	if record == nil {
		return nil
	}
	// Get the netblocks associated with this ASN
	record.Netblocks = ns.FetchOnlineNetblockData(asn)
	// Just in case
	if cidr != "" {
		record.Netblocks = UniqueAppend(record.Netblocks, cidr)
	}
	if len(record.Netblocks) == 0 {
		return nil
	}
	return record
}

func (ns *NetblockService) originLookup(addr string) (int, string) {
	var err error
	var answers []DNSAnswer

	ctx := ns.Config().DNSDialContext
	// TODO: Make the correct request based on ipv4 or ipv6 address

	// Get the AS number and CIDR for the IP address
	name := ReverseIP(addr) + ".origin.asn.cymru.com"
	// Attempt multiple times since this is UDP
	for i := 0; i < 3; i++ {
		answers, err = ResolveDNSWithDialContext(ctx, name, "TXT")
		if err == nil {
			break
		}
	}
	// Did we receive the DNS answer?
	if err != nil {
		return 0, ""
	}
	// Retrieve the ASN
	fields := strings.Split(answers[0].Data, " | ")
	asn, err := strconv.Atoi(fields[0])
	if err != nil {
		return 0, ""
	}
	return asn, strings.TrimSpace(fields[1])
}

func (ns *NetblockService) asnLookup(asn int) *ASRecord {
	var err error
	var answers []DNSAnswer

	ctx := ns.Config().DNSDialContext
	// TODO: Make the correct request based on ipv4 or ipv6 address

	// Get the AS record using the ASN
	name := "AS" + strconv.Itoa(asn) + ".asn.cymru.com"
	// Attempt multiple times since this is UDP
	for i := 0; i < 3; i++ {
		answers, err = ResolveDNSWithDialContext(ctx, name, "TXT")
		if err == nil {
			break
		}
	}
	// Did we receive the DNS answer?
	if err != nil {
		return nil
	}
	// Parse the record returned
	record := parseASNInfo(answers[0].Data)
	if record == nil {
		return nil
	}
	return record
}

func (ns *NetblockService) FetchOnlineNetblockData(asn int) []string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	conn, err := ns.Config().DialContext(ctx, "tcp", "asn.shadowserver.org:43")
	if err != nil {
		return []string{}
	}
	defer conn.Close()

	fmt.Fprintf(conn, "prefix %d\n", asn)
	reader := bufio.NewReader(conn)

	var blocks []string
	for err == nil {
		var line string

		line, err = reader.ReadString('\n')
		if len(line) > 0 {
			blocks = append(blocks, strings.TrimSpace(line))
		}
	}

	if len(blocks) == 0 {
		return []string{}
	}
	return blocks
}

func parseASNInfo(line string) *ASRecord {
	fields := strings.Split(line, " | ")

	asn, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil
	}
	// Get the allocation date into the Go Time type
	t, err := time.Parse("2006-Jan-02", strings.TrimSpace(fields[3]))
	if err != nil {
		t = time.Now()
	}
	// Obtain the portion of the description we are interested in
	parts := strings.Split(fields[4], "-")

	return &ASRecord{
		ASN:            asn,
		CC:             strings.TrimSpace(fields[1]),
		Registry:       strings.TrimSpace(fields[2]),
		AllocationDate: t,
		Description:    strings.TrimSpace(parts[len(parts)-1]),
	}
}
