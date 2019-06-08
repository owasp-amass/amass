// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"errors"
	"io/ioutil"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/OWASP/Amass/amass/core"
	"github.com/OWASP/Amass/amass/sources"
	"github.com/OWASP/Amass/amass/utils"
)

// IntelCollection is the object type used to execute a open source information gathering with Amass.
type IntelCollection struct {
	Config *core.Config
	Bus    *core.EventBus

	// The channel that will receive the results
	Output chan *core.Output

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	// Cache for the infrastructure data collected from online sources
	netLock  sync.Mutex
	netCache map[int]*core.ASNRequest

	cidrChan   chan *net.IPNet
	domainChan chan *core.Output
	activeChan chan struct{}
}

// NewIntelCollection returns an initialized IntelCollection object that has not been started yet.
func NewIntelCollection() *IntelCollection {
	return &IntelCollection{
		Config:     &core.Config{Log: log.New(ioutil.Discard, "", 0)},
		Bus:        core.NewEventBus(),
		Output:     make(chan *core.Output, 100),
		Done:       make(chan struct{}, 2),
		netCache:   make(map[int]*core.ASNRequest),
		cidrChan:   make(chan *net.IPNet, 100),
		domainChan: make(chan *core.Output, 100),
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
	t := time.NewTicker(2 * time.Second)
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

	addrinfo := core.AddressInfo{Address: ip}
	ic.activeChan <- struct{}{}
	if _, answer, err := core.ReverseDNS(addr); err == nil {
		if d := strings.TrimSpace(core.SubdomainToDomain(answer)); d != "" {
			ic.domainChan <- &core.Output{
				Name:      d,
				Domain:    d,
				Addresses: []core.AddressInfo{addrinfo},
				Tag:       core.DNS,
				Source:    "Reverse DNS",
			}
		}
	}

	ic.activeChan <- struct{}{}
	if !ic.Config.Active {
		return
	}

	for _, r := range PullCertificateNames(addr, ic.Config.Ports) {
		if d := strings.TrimSpace(r.Domain); d != "" {
			ic.domainChan <- &core.Output{
				Name:      d,
				Domain:    d,
				Addresses: []core.AddressInfo{addrinfo},
				Tag:       core.CERT,
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

	ic.Bus.Subscribe(core.NewASNTopic, ic.updateNetCache)
	defer ic.Bus.Unsubscribe(core.NewASNTopic, ic.updateNetCache)

	srcs := sources.GetAllSources(ic.Config, ic.Bus)
	// Select the data sources desired by the user
	if len(ic.Config.DisabledDataSources) > 0 {
		srcs = ic.Config.ExcludeDisabledDataSources(srcs)
	}
	// Keep only the data sources that successfully start
	var keep []core.Service
	for _, src := range srcs {
		if err := src.Start(); err != nil {
			src.Stop()
			continue
		}
		keep = append(keep, src)
	}
	srcs = keep

	// Send the ASN requests to the data sources
	for _, asn := range ic.Config.ASNs {
		for _, src := range srcs {
			src.SendASNRequest(&core.ASNRequest{ASN: asn})
		}
	}

	t := time.NewTicker(2 * time.Second)
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
	// Stop all the data sources and wait for cleanup to finish
	for _, src := range srcs {
		src.Stop()
	}
	// Process the collected netblocks
	go ic.sendNetblockCIDRs()
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

func (ic *IntelCollection) updateNetCache(req *core.ASNRequest) {
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

// LookupASNsByName returns core.ASNRequest objects for autonomous systems with
// descriptions that contain the string provided by the parameter.
func LookupASNsByName(s string) ([]*core.ASNRequest, error) {
	var records []*core.ASNRequest

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
					records = append(records, &core.ASNRequest{
						ASN:         a,
						Description: parts[1],
					})
				}
			}
		}
	}
	return records, nil
}

// ReverseWhois returns domain names that are related to the domain provided
func ReverseWhois(domain string) ([]string, error) {
	var domains []string

	sort.Strings(domains)
	return domains, nil
}
