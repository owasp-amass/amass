// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package intel

import (
	"bufio"
	"errors"
	"fmt"
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
	sf "github.com/OWASP/Amass/stringfilter"
	"github.com/OWASP/Amass/utils"
)

// Collection is the object type used to execute a open source information gathering with Amass.
type Collection struct {
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

// NewCollection returns an initialized Collection object that has not been started yet.
func NewCollection() *Collection {
	c := &Collection{
		Config:     config.NewConfig(),
		Bus:        eb.NewEventBus(),
		Output:     make(chan *requests.Output, 100),
		Done:       make(chan struct{}, 2),
		netCache:   make(map[int]*requests.ASNRequest),
		cidrChan:   make(chan *net.IPNet, 100),
		domainChan: make(chan *requests.Output, 100),
		activeChan: make(chan struct{}, 100),
	}

	c.Pool = resolvers.NewResolverPool(c.Config.Resolvers)
	if c.Pool == nil {
		return nil
	}

	return c
}

// HostedDomains uses open source intelligence to discover root domain names in the target infrastructure.
func (c *Collection) HostedDomains() error {
	if c.Output == nil {
		return errors.New("The intelligence collection did not have an output channel")
	} else if err := c.Config.CheckSettings(); err != nil {
		return err
	}
	fmt.Printf("%+v\n", c.Config)

	go c.startAddressRanges()
	go c.processCIDRs()
	go func() {
		for _, cidr := range c.Config.CIDRs {
			c.cidrChan <- cidr
		}
	}()
	c.asnsToCIDRs()

	var active bool
	filter := sf.NewStringFilter()
	t := time.NewTicker(5 * time.Second)

	if c.Config.Timeout > 0 {
		time.AfterFunc(time.Duration(c.Config.Timeout)*time.Second, func() {
			c.Config.Log.Printf("Enumeration exceeded provided timeout")
			close(c.Done)
		})
	}

loop:
	for {
		select {
		case <-c.Done:
			break loop
		case <-t.C:
			if !active {
				close(c.Done)
			}
			active = false
		case <-c.activeChan:
			active = true
		case d := <-c.domainChan:
			active = true
			if !filter.Duplicate(d.Domain) {
				c.Output <- d
			}
		}
	}
	t.Stop()
	close(c.Output)
	return nil
}

func (c *Collection) startAddressRanges() {
	for _, addr := range c.Config.Addresses {
		c.Config.SemMaxDNSQueries.Acquire(1)
		go c.investigateAddr(addr.String())
	}
}

func (c *Collection) processCIDRs() {
	for {
		select {
		case <-c.Done:
			return
		case cidr := <-c.cidrChan:
			// Skip IPv6 netblocks, since they are simply too large
			if ip := cidr.IP.Mask(cidr.Mask); utils.IsIPv6(ip) {
				continue
			}

			for _, addr := range utils.NetHosts(cidr) {
				c.Config.SemMaxDNSQueries.Acquire(1)
				go c.investigateAddr(addr.String())
			}
		}
	}
}

func (c *Collection) investigateAddr(addr string) {
	defer c.Config.SemMaxDNSQueries.Release(1)

	ip := net.ParseIP(addr)
	if ip == nil {
		return
	}

	addrinfo := requests.AddressInfo{Address: ip}
	c.activeChan <- struct{}{}
	if _, answer, err := c.Pool.ReverseDNS(addr); err == nil {
		if d := strings.TrimSpace(c.Pool.SubdomainToDomain(answer)); d != "" {
			c.domainChan <- &requests.Output{
				Name:      d,
				Domain:    d,
				Addresses: []requests.AddressInfo{addrinfo},
				Tag:       requests.DNS,
				Source:    "Reverse DNS",
			}
		}
	}

	c.activeChan <- struct{}{}
	if !c.Config.Active {
		return
	}

	for _, name := range utils.PullCertificateNames(addr, c.Config.Ports) {
		if n := strings.TrimSpace(name); n != "" {
			c.domainChan <- &requests.Output{
				Name:      n,
				Domain:    c.Pool.SubdomainToDomain(n),
				Addresses: []requests.AddressInfo{addrinfo},
				Tag:       requests.CERT,
				Source:    "Active Cert",
			}
		}
	}
	c.activeChan <- struct{}{}
}

func (c *Collection) asnsToCIDRs() {
	if len(c.Config.ASNs) == 0 {
		return
	}

	c.Bus.Subscribe(requests.NewASNTopic, c.updateNetCache)
	defer c.Bus.Unsubscribe(requests.NewASNTopic, c.updateNetCache)

	srcs := sources.GetAllSources(c.Config, c.Bus, c.Pool)
	// Select the data sources desired by the user
	if len(c.Config.DisabledDataSources) > 0 {
		srcs = ExcludeDisabledDataSources(srcs, c.Config)
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
	for _, asn := range c.Config.ASNs {
		for _, src := range srcs {
			src.SendASNRequest(&requests.ASNRequest{ASN: asn})
		}
	}

	t := time.NewTicker(5 * time.Second)
	defer t.Stop()
	defer c.sendNetblockCIDRs()
	for {
		select {
		case <-c.Done:
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

func (c *Collection) sendNetblockCIDRs() {
	c.netLock.Lock()
	defer c.netLock.Unlock()

	filter := sf.NewStringFilter()
	for _, record := range c.netCache {
		for netblock := range record.Netblocks {
			_, ipnet, err := net.ParseCIDR(netblock)
			if err == nil && !filter.Duplicate(ipnet.String()) {
				c.cidrChan <- ipnet
			}
		}
	}
}

func (c *Collection) updateNetCache(req *requests.ASNRequest) {
	c.netLock.Lock()
	defer c.netLock.Unlock()

	if _, found := c.netCache[req.ASN]; !found {
		c.netCache[req.ASN] = req
		return
	}

	entry := c.netCache[req.ASN]
	// This is additional information for an ASN entry
	if entry.Prefix == "" && req.Prefix != "" {
		entry.Prefix = req.Prefix
	}
	if entry.CC == "" && req.CC != "" {
		entry.CC = req.CC
	}
	if entry.Registry == "" && req.Registry != "" {
		entry.Registry = req.Registry
	}
	if entry.AllocationDate.IsZero() && !req.AllocationDate.IsZero() {
		entry.AllocationDate = req.AllocationDate
	}
	if entry.Description == "" && req.Description != "" {
		entry.Description = req.Description
	}
	entry.Netblocks.Union(req.Netblocks)
	c.netCache[req.ASN] = entry
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
func (c *Collection) ReverseWhois() error {
	filter := sf.NewStringFilter()

	collect := func(req *requests.WhoisRequest) {
		for _, d := range req.NewDomains {
			if !filter.Duplicate(d) {
				c.Output <- &requests.Output{
					Name:   d,
					Domain: d,
					Tag:    req.Tag,
					Source: req.Source,
				}
			}
		}
	}
	c.Bus.Subscribe(requests.NewWhoisTopic, collect)
	defer c.Bus.Unsubscribe(requests.NewWhoisTopic, collect)

	srcs := sources.GetAllSources(c.Config, c.Bus, c.Pool)
	// Select the data sources desired by the user
	if len(c.Config.DisabledDataSources) > 0 {
		srcs = ExcludeDisabledDataSources(srcs, c.Config)
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
	for _, domain := range c.Config.Domains() {
		for _, src := range srcs {
			src.SendWhoisRequest(&requests.WhoisRequest{Domain: domain})
		}
	}

	t := time.NewTicker(5 * time.Second)
loop:
	for {
		select {
		case <-c.Done:
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
	close(c.Output)
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
