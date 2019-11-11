// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/stringset"
)

// Robtex is the Service that handles access to the Robtex data source.
type Robtex struct {
	BaseService

	SourceType string
}

type robtexJSON struct {
	Name string `json:"rrname"`
	Data string `json:"rrdata"`
	Type string `json:"rrtype"`
}

// NewRobtex returns he object initialized, but not yet started.
func NewRobtex(sys System) *Robtex {
	r := &Robtex{SourceType: requests.API}

	r.BaseService = *NewBaseService(r, "Robtex", sys)
	return r
}

// Type implements the Service interface.
func (r *Robtex) Type() string {
	return r.SourceType
}

// OnStart implements the Service interface.
func (r *Robtex) OnStart() error {
	r.BaseService.OnStart()

	r.SetRateLimit(3 * time.Second)
	return nil
}

// OnASNRequest implements the Service interface.
func (r *Robtex) OnASNRequest(ctx context.Context, req *requests.ASNRequest) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return
	}

	if req.Address == "" && req.ASN == 0 {
		return
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, r.String())

	if req.Address != "" {
		r.executeASNAddrQuery(ctx, req.Address)
		return
	}

	r.executeASNQuery(ctx, req.ASN)
}

// OnDNSRequest implements the Service interface.
func (r *Robtex) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, r.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", r.String(), req.Domain))

	url := "https://freeapi.robtex.com/pdns/forward/" + req.Domain
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	ips := stringset.New()
	for _, line := range r.parseDNSJSON(page) {
		if line.Type == "A" {
			ips.Insert(line.Data)
			/*
				// Inform the Address Service of this finding
				bus.Publish(requests.NewAddrTopic, &requests.AddrRequest{
					Address: line.Data,
					Domain:  req.Domain,
					Tag:     r.Type(),
					Source:  r.String(),
				})
			*/
		} else if line.Type == "NS" || line.Type == "MX" {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   strings.Trim(line.Data, "."),
				Domain: req.Domain,
				Tag:    r.Type(),
				Source: r.String(),
			})
		}
	}

loop:
	for ip := range ips {
		select {
		case <-r.Quit():
			return
		default:
			r.CheckRateLimit()
			bus.Publish(requests.SetActiveTopic, r.String())

			url = "https://freeapi.robtex.com/pdns/reverse/" + ip
			pdns, err := http.RequestWebPage(url, nil, nil, "", "")
			if err != nil {
				bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
				continue loop
			}

			for _, line := range r.parseDNSJSON(pdns) {
				n := strings.Trim(line.Name, ".")

				if d := cfg.WhichDomain(n); d != "" {
					bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
						Name:   n,
						Domain: d,
						Tag:    r.Type(),
						Source: r.String(),
					})
				}
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
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
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
	bus.Publish(requests.SetActiveTopic, r.String())

	req := r.origin(ctx, ipnet.IP.String())
	if req == nil {
		return
	}

	req.Netblocks.Union(blocks)
	bus.Publish(requests.NewASNTopic, req)
}

func (r *Robtex) executeASNAddrQuery(ctx context.Context, addr string) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	req := r.origin(ctx, addr)
	if req == nil {
		return
	}

	req.Netblocks.Union(r.netblocks(ctx, req.ASN))
	bus.Publish(requests.NewASNTopic, req)
}

func (r *Robtex) origin(ctx context.Context, addr string) *requests.ASNRequest {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return nil
	}

	if ip := net.ParseIP(addr); ip == nil || !amassnet.IsIPv4(ip) {
		return nil
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, r.String())

	url := "https://freeapi.robtex.com/ipquery/" + addr
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
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
		if cfg.IsDomainInScope(n.Name) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.System().Pool().SubdomainToDomain(n.Name),
				Tag:    r.Type(),
				Source: r.String(),
			})
		}
	}

	for _, n := range ipinfo.ActiveDNSHistory {
		if cfg.IsDomainInScope(n.Name) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.System().Pool().SubdomainToDomain(n.Name),
				Tag:    r.Type(),
				Source: r.String(),
			})
		}
	}

	for _, n := range ipinfo.PassiveDNS {
		if cfg.IsDomainInScope(n.Name) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.System().Pool().SubdomainToDomain(n.Name),
				Tag:    r.Type(),
				Source: r.String(),
			})
		}
	}

	for _, n := range ipinfo.PassiveDNSHistory {
		if cfg.IsDomainInScope(n.Name) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.System().Pool().SubdomainToDomain(n.Name),
				Tag:    r.Type(),
				Source: r.String(),
			})
		}
	}

	if ipinfo.ASN == 0 {
		bus.Publish(requests.LogTopic,
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

	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return netblocks
	}

	r.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, r.String())

	url := "https://freeapi.robtex.com/asquery/" + strconv.Itoa(asn)
	page, err := http.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
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
		bus.Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to acquire netblocks for ASN %d", r.String(), asn),
		)
	}
	return netblocks
}
