// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package intel

import (
	"bufio"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/services/sources"
	"github.com/OWASP/Amass/utils"
)

// IntelCollection is the object type used to execute a open source information gathering with Amass.
type IntelCollection struct {
	Config *config.Config
	Bus    *eb.EventBus
	Pool   *resolvers.ResolverPool

	// The channel that will receive the results
	Output chan *requests.Output

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	// Cache for the infrastructure data collected from online sources
	netLock  sync.Mutex
	netCache map[int]*requests.ASNRequest

	cidrChan   chan *net.IPNet
	domainChan chan *requests.Output
	activeChan chan struct{}
}

// NewIntelCollection returns an initialized IntelCollection object that has not been started yet.
func NewIntelCollection() *IntelCollection {
	return &IntelCollection{
		Config:     &config.Config{Log: log.New(ioutil.Discard, "", 0)},
		Bus:        eb.NewEventBus(),
		Pool:       resolvers.NewResolverPool(nil),
		Output:     make(chan *requests.Output, 100),
		Done:       make(chan struct{}, 2),
		netCache:   make(map[int]*requests.ASNRequest),
		cidrChan:   make(chan *net.IPNet, 100),
		domainChan: make(chan *requests.Output, 100),
		activeChan: make(chan struct{}, 100),
	}
}

// HostedDomains uses open source intelligence to discover root domain names in the target infrastructure.
func (ic *IntelCollection) HostedDomains() error {
	if ic.Output == nil {
		return errors.New("The intelligence collection did not have an output channel")
	} else if err := ic.Config.CheckSettings(); err != nil {
		return err
	}

	go ic.startAddressRanges()
	go ic.processCIDRs()
	go func() {
		for _, cidr := range ic.Config.CIDRs {
			ic.cidrChan <- cidr
		}
	}()
	ic.asnsToCIDRs()

	var active bool
	filter := utils.NewStringFilter()
	t := time.NewTicker(5 * time.Second)
loop:
	for {
		select {
		case <-ic.Done:
			break loop
		case <-t.C:
			if !active {
				close(ic.Done)
			}
			active = false
		case <-ic.activeChan:
			active = true
		case d := <-ic.domainChan:
			active = true
			if !filter.Duplicate(d.Domain) {
				ic.Output <- d
			}
		}
	}
	t.Stop()
	close(ic.Output)
	return nil
}

func (ic *IntelCollection) startAddressRanges() {
	for _, addr := range ic.Config.Addresses {
		ic.Config.SemMaxDNSQueries.Acquire(1)
		go ic.investigateAddr(addr.String())
	}
}

func (ic *IntelCollection) processCIDRs() {
	for {
		select {
		case <-ic.Done:
			return
		case cidr := <-ic.cidrChan:
			for _, addr := range utils.NetHosts(cidr) {
				ic.Config.SemMaxDNSQueries.Acquire(1)
				go ic.investigateAddr(addr.String())
			}
		}
	}
}

func (ic *IntelCollection) investigateAddr(addr string) {
	defer ic.Config.SemMaxDNSQueries.Release(1)

	ip := net.ParseIP(addr)
	if ip == nil {
		return
	}

	addrinfo := requests.AddressInfo{Address: ip}
	ic.activeChan <- struct{}{}
	if _, answer, err := ic.Pool.ReverseDNS(addr); err == nil {
		if d := strings.TrimSpace(ic.Pool.SubdomainToDomain(answer)); d != "" {
			ic.domainChan <- &requests.Output{
				Name:      d,
				Domain:    d,
				Addresses: []requests.AddressInfo{addrinfo},
				Tag:       requests.DNS,
				Source:    "Reverse DNS",
			}
		}
	}

	ic.activeChan <- struct{}{}
	if !ic.Config.Active {
		return
	}

	for _, name := range utils.PullCertificateNames(addr, ic.Config.Ports) {
		if n := strings.TrimSpace(name); n != "" {
			ic.domainChan <- &requests.Output{
				Name:      n,
				Domain:    ic.Pool.SubdomainToDomain(n),
				Addresses: []requests.AddressInfo{addrinfo},
				Tag:       requests.CERT,
				Source:    "Active Cert",
			}
		}
	}
	ic.activeChan <- struct{}{}
}

func (ic *IntelCollection) asnsToCIDRs() {
	if len(ic.Config.ASNs) == 0 {
		return
	}

	ic.Bus.Subscribe(requests.NewASNTopic, ic.updateNetCache)
	defer ic.Bus.Unsubscribe(requests.NewASNTopic, ic.updateNetCache)

	srcs := sources.GetAllSources(ic.Config, ic.Bus, ic.Pool)
	// Select the data sources desired by the user
	if len(ic.Config.DisabledDataSources) > 0 {
		srcs = ExcludeDisabledDataSources(srcs, ic.Config)
	}
	// Keep only the data sources that successfully start
	var keep []services.Service
	for _, src := range srcs {
		if err := src.Start(); err != nil {
			src.Stop()
			continue
		}
		keep = append(keep, src)
		defer src.Stop()
	}
	srcs = keep

	// Send the ASN requests to the data sources
	for _, asn := range ic.Config.ASNs {
		for _, src := range srcs {
			src.SendASNRequest(&requests.ASNRequest{ASN: asn})
		}
	}

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	defer ic.sendNetblockCIDRs()
	for {
		select {
		case <-ic.Done:
			return
		case <-t.C:
			done := true
			for _, src := range srcs {
				if src.IsActive() {
					done = false
					break
				}
			}
			if done {
				return
			}
		}
	}
}

func (ic *IntelCollection) sendNetblockCIDRs() {
	ic.netLock.Lock()
	defer ic.netLock.Unlock()

	filter := utils.NewStringFilter()
	for _, record := range ic.netCache {
		for _, netblock := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(netblock)
			if err == nil && !filter.Duplicate(ipnet.String()) {
				ic.cidrChan <- ipnet
			}
		}
	}
}

func (ic *IntelCollection) updateNetCache(req *requests.ASNRequest) {
	ic.netLock.Lock()
	defer ic.netLock.Unlock()

	if _, found := ic.netCache[req.ASN]; !found {
		ic.netCache[req.ASN] = req
		return
	}

	c := ic.netCache[req.ASN]
	// This is additional information for an ASN entry
	if c.Prefix == "" && req.Prefix != "" {
		c.Prefix = req.Prefix
	}
	if c.CC == "" && req.CC != "" {
		c.CC = req.CC
	}
	if c.Registry == "" && req.Registry != "" {
		c.Registry = req.Registry
	}
	if c.AllocationDate.IsZero() && !req.AllocationDate.IsZero() {
		c.AllocationDate = req.AllocationDate
	}
	if c.Description == "" && req.Description != "" {
		c.Description = req.Description
	}
	c.Netblocks = utils.UniqueAppend(c.Netblocks, req.Netblocks...)
	ic.netCache[req.ASN] = c
}

// LookupASNsByName returns requests.ASNRequest objects for autonomous systems with
// descriptions that contain the string provided by the parameter.
func LookupASNsByName(s string) ([]*requests.ASNRequest, error) {
	var records []*requests.ASNRequest

	s = strings.ToLower(s)
	url := "https://raw.githubusercontent.com/OWASP/Amass/master/wordlists/asnlist.txt"
	page, err := utils.RequestWebPage(url, nil, nil, "", "")
	if err != nil {
		return records, err
	}

	scanner := bufio.NewScanner(strings.NewReader(page))
	for scanner.Scan() {
		line := scanner.Text()

		if err := scanner.Err(); err == nil {
			parts := strings.Split(strings.TrimSpace(line), ",")

			if strings.Contains(strings.ToLower(parts[1]), s) {
				a, err := strconv.Atoi(parts[0])
				if err == nil {
					records = append(records, &requests.ASNRequest{
						ASN:         a,
						Description: parts[1],
					})
				}
			}
		}
	}
	return records, nil
}

// ReverseWhois returns domain names that are related to the domains provided
func (ic *IntelCollection) ReverseWhois() error {
	filter := utils.NewStringFilter()

	collect := func(req *requests.WhoisRequest) {
		for _, d := range req.NewDomains {
			if !filter.Duplicate(d) {
				ic.Output <- &requests.Output{
					Name:   d,
					Domain: d,
					Tag:    req.Tag,
					Source: req.Source,
				}
			}
		}
	}
	ic.Bus.Subscribe(requests.NewWhoisTopic, collect)
	defer ic.Bus.Unsubscribe(requests.NewWhoisTopic, collect)

	srcs := sources.GetAllSources(ic.Config, ic.Bus, ic.Pool)
	// Select the data sources desired by the user
	if len(ic.Config.DisabledDataSources) > 0 {
		srcs = ExcludeDisabledDataSources(srcs, ic.Config)
	}
	// Keep only the data sources that successfully start
	var keep []services.Service
	for _, src := range srcs {
		if err := src.Start(); err != nil {
			src.Stop()
			continue
		}
		keep = append(keep, src)
		defer src.Stop()
	}
	srcs = keep

	// Send the whois requests to the data sources
	for _, domain := range ic.Config.Domains() {
		for _, src := range srcs {
			src.SendWhoisRequest(&requests.WhoisRequest{Domain: domain})
		}
	}

	t := time.NewTicker(5 * time.Second)
loop:
	for {
		select {
		case <-ic.Done:
			break loop
		case <-t.C:
			done := true
			for _, src := range srcs {
				if src.IsActive() {
					done = false
					break
				}
			}
			if done {
				break loop
			}
		}
	}
	t.Stop()
	close(ic.Output)
	return nil
}

// ExcludeDisabledDataSources returns a list of data sources excluding DisabledDataSources.
func ExcludeDisabledDataSources(srvs []services.Service, cfg *config.Config) []services.Service {
	var enabled []services.Service

	for _, s := range srvs {
		include := true

		for _, disabled := range cfg.DisabledDataSources {
			if strings.EqualFold(disabled, s.String()) {
				include = false
				break
			}
		}
		if include {
			enabled = append(enabled, s)
		}
	}
	return enabled
}
