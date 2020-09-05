// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
	"github.com/OWASP/Amass/v3/systems"
)

// Robtex is the Service that handles access to the Robtex data source.
type Robtex struct {
	requests.BaseService

	SourceType string
	sys        systems.System
}

type robtexJSON struct {
	Name string `json:"rrname"`
	Data string `json:"rrdata"`
	Type string `json:"rrtype"`
}

// NewRobtex returns he object initialized, but not yet started.
func NewRobtex(sys systems.System) *Robtex {
	r := &Robtex{
		SourceType: requests.API,
		sys:        sys,
	}

	r.BaseService = *requests.NewBaseService(r, "Robtex")
	return r
}

// Type implements the Service interface.
func (r *Robtex) Type() string {
	return r.SourceType
}

// OnStart implements the Service interface.
func (r *Robtex) OnStart() error {
	r.BaseService.OnStart()

	r.SetRateLimit(6 * time.Second)
	return nil
}

// OnASNRequest implements the Service interface.
func (r *Robtex) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	if req.Address == "" && req.ASN == 0 {
		return
	}

	r.CheckRateLimit()
	if req.Address != "" {
		r.executeASNAddrQuery(ctx, req.Address)
		return
	}

	r.executeASNQuery(ctx, req.ASN)
}

// OnDNSRequest implements the Service interface.
func (r *Robtex) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, r.String())
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", r.String(), req.Domain))

	url := "https://freeapi.robtex.com/pdns/forward/" + req.Domain
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	ips := stringset.New()
	for _, line := range r.parseDNSJSON(page) {
		if line.Type == "A" {
			ips.Insert(line.Data)
		} else if line.Type == "NS" || line.Type == "MX" {
			name := strings.Trim(line.Data, ".")

			if cfg.IsDomainInScope(name) {
				genNewNameEvent(ctx, r.sys, r, name)
			}
		}
	}

loop:
	for ip := range ips {
		select {
		case <-r.Quit():
			return
		default:
			r.CheckRateLimit()
			bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, r.String())

			url = "https://freeapi.robtex.com/pdns/reverse/" + ip
			pdns, err := http.RequestWebPage(url, nil, nil, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
					fmt.Sprintf("%s: %s: %v", r.String(), url, err))
				continue loop
			}

			for _, line := range r.parseDNSJSON(pdns) {
				name := strings.Trim(line.Name, ".")

				genNewNameEvent(ctx, r.sys, r, name)
			}
		}
	}
}

func (r *Robtex) parseDNSJSON(page string) []robtexJSON {
	var lines []robtexJSON

	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		// Get the next line of JSON
		line := scanner.Text()
		if line == "" {
			continue
		}

		var j robtexJSON
		err := json.Unmarshal([]byte(line), &j)
		if err != nil {
			continue
		}
		lines = append(lines, j)
	}
	return lines
}

func (r *Robtex) executeASNQuery(ctx context.Context, asn int) {
	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	blocks := r.netblocks(ctx, asn)
	if len(blocks) == 0 {
		return
	}

	_, ipnet, err := net.ParseCIDR(blocks.Slice()[0])
	if err != nil {
		return
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, r.String())

	req := r.origin(ctx, ipnet.IP.String())
	if req == nil {
		return
	}

	req.Netblocks.Union(blocks)
	bus.Publish(requests.NewASNTopic, eventbus.PriorityHigh, req)
}

func (r *Robtex) executeASNAddrQuery(ctx context.Context, addr string) {
	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	req := r.origin(ctx, addr)
	if req == nil {
		return
	}

	req.Netblocks.Union(r.netblocks(ctx, req.ASN))
	bus.Publish(requests.NewASNTopic, eventbus.PriorityHigh, req)
}

func (r *Robtex) origin(ctx context.Context, addr string) *requests.ASNRequest {
	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return nil
	}

	if ip := net.ParseIP(addr); ip == nil || !amassnet.IsIPv4(ip) {
		return nil
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, r.String())

	url := "https://freeapi.robtex.com/ipquery/" + addr
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return nil
	}
	// Extract the network information
	var ipinfo struct {
		Status    string `json:"status"`
		ASN       int    `json:"as"`
		Prefix    string `json:"bgproute"`
		ASName    string `json:"asname"`
		ASDesc    string `json:"asdesc"`
		WhoisDesc string `json:"whoisdesc"`
		ActiveDNS []struct {
			Name string `json:"o"`
		} `json:"act"`
		ActiveDNSHistory []struct {
			Name string `json:"o"`
		} `json:"acth"`
		PassiveDNS []struct {
			Name string `json:"o"`
		} `json:"pas"`
		PassiveDNSHistory []struct {
			Name string `json:"o"`
		} `json:"pash"`
	}
	if err := json.Unmarshal([]byte(page), &ipinfo); err != nil || ipinfo.Status != "ok" {
		return nil
	}

	for _, n := range ipinfo.ActiveDNS {
		genNewNameEvent(ctx, r.sys, r, n.Name)
	}

	for _, n := range ipinfo.ActiveDNSHistory {
		genNewNameEvent(ctx, r.sys, r, n.Name)
	}

	for _, n := range ipinfo.PassiveDNS {
		genNewNameEvent(ctx, r.sys, r, n.Name)
	}

	for _, n := range ipinfo.PassiveDNSHistory {
		genNewNameEvent(ctx, r.sys, r, n.Name)
	}

	if ipinfo.ASN == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: %s: Failed to parse the origin response: %v", r.String(), url, err),
		)
		return nil
	}

	desc := ipinfo.ASName
	if len(desc) < len(ipinfo.ASDesc) {
		desc = ipinfo.ASDesc
	}
	if len(strings.Split(desc, "-")) < 2 && len(desc) < len(ipinfo.WhoisDesc) {
		desc = ipinfo.WhoisDesc
	}

	return &requests.ASNRequest{
		Address:     addr,
		ASN:         ipinfo.ASN,
		Prefix:      ipinfo.Prefix,
		Description: desc,
		Netblocks:   stringset.New(ipinfo.Prefix),
		Tag:         r.Type(),
		Source:      r.String(),
	}
}

func (r *Robtex) netblocks(ctx context.Context, asn int) stringset.Set {
	netblocks := stringset.New()

	_, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return netblocks
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, eventbus.PriorityCritical, r.String())

	url := "https://freeapi.robtex.com/asquery/" + strconv.Itoa(asn)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return netblocks
	}
	// Extract the network information
	var n struct {
		Status   string `json:"status"`
		Networks []struct {
			CIDR string `json:"n"`
		} `json:"nets"`
	}
	if err := json.Unmarshal([]byte(page), &n); err != nil || n.Status != "ok" {
		return netblocks
	}

	for _, net := range n.Networks {
		netblocks.Insert(net.CIDR)
	}

	if len(netblocks) == 0 {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
			fmt.Sprintf("%s: Failed to acquire netblocks for ASN %d", r.String(), asn),
		)
	}
	return netblocks
}
