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

	// Queue for requests waiting for Shadowserver data
	queue []*AmassRequest

	// Data cached from the Shadowserver requests
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

	pull := time.NewTicker(5 * time.Second)
	defer pull.Stop()
loop:
	for {
		select {
		case req := <-ns.Input():
			ns.SetActive(true)
			if data := ns.cacheFetch(req.Address); data != nil {
				ns.sendRequest(req, data)
			} else {
				ns.add(req)
			}
		case <-pull.C:
			go ns.netblockLookup()
		case <-t.C:
			ns.SetActive(false)
		case <-ns.Quit():
			break loop
		}
	}
}

func (ns *NetblockService) add(req *AmassRequest) {
	ns.Lock()
	defer ns.Unlock()

	ns.queue = append(ns.queue, req)
}

func (ns *NetblockService) next() *AmassRequest {
	ns.Lock()
	defer ns.Unlock()

	var next *AmassRequest
	if len(ns.queue) == 1 {
		next = ns.queue[0]
		ns.queue = []*AmassRequest{}
	} else if len(ns.queue) > 1 {
		next = ns.queue[0]
		ns.queue = ns.queue[1:]
	}
	return next
}

func (ns *NetblockService) sendRequest(req *AmassRequest, data *cidrData) {
	ns.SetActive(true)
	// Add the netblock to the request and send it on it's way
	req.Netblock = data.Netblock
	req.ASN = data.Record.ASN
	req.ISP = data.Record.ISP
	ns.SendOut(req)
}

func (ns *NetblockService) cacheFetch(addr string) *cidrData {
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

func (ns *NetblockService) cacheInsert(cidr string, entry *cidrData) {
	ns.Lock()
	defer ns.Unlock()

	ns.cache[cidr] = entry
}

func (ns *NetblockService) netblockLookup() {
	req := ns.next()
	// Empty as much of the queue as possible
	for req != nil {
		data := ns.cacheFetch(req.Address)
		if data == nil {
			break
		}
		ns.sendRequest(req, data)
		req = ns.next()
	}
	// Empty queue?
	if req == nil {
		return
	}
	// Perform a Shadowserver lookup
	ns.SetActive(true)
	// Get the AS record for the IP address
	record, err := recon.IPToASRecord(req.Address)
	if err != nil {
		return
	}
	// Get the netblocks associated with the ASN
	netblocks, err := recon.ASNToNetblocks(record.ASN)
	if err != nil {
		return
	}
	// Insert all the netblocks into the cache
	ip := net.ParseIP(req.Address)
	for _, nb := range netblocks {
		_, cidr, err := net.ParseCIDR(nb)
		if err != nil {
			continue
		}

		data := &cidrData{
			Netblock: cidr,
			Record:   record,
		}
		ns.cacheInsert(cidr.String(), data)

		// If this netblock belongs to the request, send it
		if cidr.Contains(ip) {
			ns.sendRequest(req, data)
		}
	}
}
