// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// Robtex is the Service that handles access to the Robtex data source.
type Robtex struct {
	services.BaseService

	SourceType string
	RateLimit  time.Duration
}

type robtexJSON struct {
	Name string `json:"rrname"`
	Data string `json:"rrdata"`
	Type string `json:"rrtype"`
}

// NewRobtex returns he object initialized, but not yet started.
func NewRobtex(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *Robtex {
	r := &Robtex{
		SourceType: requests.API,
		RateLimit:  time.Second,
	}

	r.BaseService = *services.NewBaseService(r, "Robtex", cfg, bus, pool)
	return r
}

// OnStart implements the Service interface
func (r *Robtex) OnStart() error {
	r.BaseService.OnStart()

	r.Bus().Subscribe(requests.IPToASNTopic, r.SendASNRequest)
	go r.processRequests()
	return nil
}

func (r *Robtex) processRequests() {
	last := time.Now().Truncate(10 * time.Minute)
loop:
	for {
		select {
		case <-r.Quit():
			return
		case dns := <-r.DNSRequestChan():
			if time.Now().Sub(last) < r.RateLimit {
				time.Sleep(r.RateLimit)
			}
			last = time.Now()
			if r.Config().IsDomainInScope(dns.Domain) {
				r.executeDNSQuery(dns.Domain)
			}
			last = time.Now()
		case asn := <-r.ASNRequestChan():
			if asn.Address == "" && asn.ASN == 0 {
				continue loop
			}
			if time.Now().Sub(last) < r.RateLimit {
				time.Sleep(r.RateLimit)
			}
			last = time.Now()
			if asn.Address != "" {
				r.executeASNAddrQuery(asn.Address)
			} else {
				r.executeASNQuery(asn.ASN)
			}
			last = time.Now()
		case <-r.AddrRequestChan():
		case <-r.WhoisRequestChan():
		}
	}
}

func (r *Robtex) executeDNSQuery(domain string) {
	var ips []string

	re := r.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	r.SetActive()
	url := "https://freeapi.robtex.com/pdns/forward/" + domain
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
		return
	}

	for _, line := range r.parseDNSJSON(page) {
		if line.Type == "A" {
			ips = utils.UniqueAppend(ips, line.Data)
			// Inform the Address Service of this finding
			r.Bus().Publish(requests.NewAddrTopic, &requests.AddrRequest{
				Address: line.Data,
				Domain:  domain,
				Tag:     r.SourceType,
				Source:  r.String(),
			})
		}
	}

	var names []string
	t := time.NewTicker(500 * time.Millisecond)
	defer t.Stop()
loop:
	for _, ip := range ips {
		r.SetActive()

		select {
		case <-r.Quit():
			break loop
		case <-t.C:
			url = "https://freeapi.robtex.com/pdns/reverse/" + ip
			pdns, err := utils.RequestWebPage(url, nil, nil, "", "")
			if err != nil {
				r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
				continue
			}

			for _, line := range r.parseDNSJSON(pdns) {
				names = utils.UniqueAppend(names, line.Name)
			}
		}
	}

	for _, name := range names {
		if r.Config().IsDomainInScope(name) {
			r.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: domain,
				Tag:    r.SourceType,
				Source: r.String(),
			})
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

func (r *Robtex) executeASNQuery(asn int) {
	r.SetActive()
	blocks := r.netblocks(asn)
	if len(blocks) == 0 {
		return
	}

	_, ipnet, err := net.ParseCIDR(blocks[0])
	if err != nil {
		return
	}

	r.SetActive()
	time.Sleep(r.RateLimit)
	req := r.origin(ipnet.IP.String())
	if req == nil {
		return
	}

	req.Netblocks = utils.UniqueAppend(req.Netblocks, blocks...)
	r.Bus().Publish(requests.NewASNTopic, req)
}

func (r *Robtex) executeASNAddrQuery(addr string) {
	r.SetActive()
	req := r.origin(addr)
	if req == nil {
		return
	}

	r.SetActive()
	time.Sleep(r.RateLimit)
	req.Netblocks = utils.UniqueAppend(req.Netblocks, r.netblocks(req.ASN)...)
	r.Bus().Publish(requests.NewASNTopic, req)
}

func (r *Robtex) origin(addr string) *requests.ASNRequest {
	if ip := net.ParseIP(addr); ip == nil || !utils.IsIPv4(ip) {
		return nil
	}

	r.SetActive()
	url := "https://freeapi.robtex.com/ipquery/" + addr
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
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
		if r.Config().IsDomainInScope(n.Name) {
			r.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.Pool().SubdomainToDomain(n.Name),
				Tag:    r.SourceType,
				Source: r.String(),
			})
		}
	}

	for _, n := range ipinfo.ActiveDNSHistory {
		if r.Config().IsDomainInScope(n.Name) {
			r.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.Pool().SubdomainToDomain(n.Name),
				Tag:    r.SourceType,
				Source: r.String(),
			})
		}
	}

	for _, n := range ipinfo.PassiveDNS {
		if r.Config().IsDomainInScope(n.Name) {
			r.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.Pool().SubdomainToDomain(n.Name),
				Tag:    r.SourceType,
				Source: r.String(),
			})
		}
	}

	for _, n := range ipinfo.PassiveDNSHistory {
		if r.Config().IsDomainInScope(n.Name) {
			r.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   n.Name,
				Domain: r.Pool().SubdomainToDomain(n.Name),
				Tag:    r.SourceType,
				Source: r.String(),
			})
		}
	}

	if ipinfo.ASN == 0 {
		r.Bus().Publish(requests.LogTopic,
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
		ASN:         ipinfo.ASN,
		Prefix:      ipinfo.Prefix,
		Description: desc,
		Netblocks:   []string{ipinfo.Prefix},
		Tag:         r.SourceType,
		Source:      r.String(),
	}
}

func (r *Robtex) netblocks(asn int) []string {
	var netblocks []string

	r.SetActive()
	url := "https://freeapi.robtex.com/asquery/" + strconv.Itoa(asn)
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		r.Bus().Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", r.String(), url, err))
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
		netblocks = utils.UniqueAppend(netblocks, net.CIDR)
	}

	if len(netblocks) == 0 {
		r.Bus().Publish(requests.LogTopic,
			fmt.Sprintf("%s: Failed to acquire netblocks for ASN %d", r.String(), asn),
		)
	}
	return netblocks
}
