// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"net"
	"time"

	"github.com/caffix/recon"
)

type cidrData struct {
	Netblock *net.IPNet
	Record   *recon.ASRecord
}

type NetblockService struct {
	BaseAmassService

	cache map[string]*cidrData
}

func NewNetblockService(in, out chan *AmassRequest, config *AmassConfig) *NetblockService {
	ns := &NetblockService{cache: make(map[string]*cidrData)}

	ns.BaseAmassService = *NewBaseAmassService("Netblock Service", config, ns)

	ns.input = in
	ns.output = out
	return ns
}

func (ns *NetblockService) OnStart() error {
	ns.BaseAmassService.OnStart()

	go ns.processRequests()
	return nil
}

func (ns *NetblockService) OnStop() error {
	ns.BaseAmassService.OnStop()
	return nil
}

func (ns *NetblockService) processRequests() {
	t := time.NewTicker(30 * time.Second)
	defer t.Stop()
loop:
	for {
		select {
		case req := <-ns.Input():
			go ns.performNetblockLookup(req)
		case <-t.C:
			ns.SetActive(false)
		case <-ns.Quit():
			break loop
		}
	}
}

func (ns *NetblockService) cidrCacheEntry(addr string) *cidrData {
	ns.Lock()
	defer ns.Unlock()

	var result *cidrData
	// Check the cache for which CIDR this IP address falls within
	ip := net.ParseIP(addr)
	for _, data := range ns.cache {
		if data.Netblock.Contains(ip) {
			result = data
			break
		}
	}
	return result
}

func (ns *NetblockService) setCIDRCacheEntry(cidr string, entry *cidrData) {
	ns.Lock()
	defer ns.Unlock()

	ns.cache[cidr] = entry
}

func (ns *NetblockService) performNetblockLookup(req *AmassRequest) {
	ns.SetActive(true)

	answer := ns.cidrCacheEntry(req.Address)
	// If the information was not within the cache, perform the lookup
	if answer == nil {
		record, cidr, err := recon.IPToCIDR(req.Address)
		if err == nil {
			data := &cidrData{
				Netblock: cidr,
				Record:   record,
			}

			ns.setCIDRCacheEntry(cidr.String(), data)
			answer = data
		}
	}
	// Add the netblock to the request and send it on it's way
	if answer != nil {
		req.Netblock = answer.Netblock
		req.ASN = answer.Record.ASN
		req.ISP = answer.Record.ISP
		ns.SendOut(req)
	}
}
