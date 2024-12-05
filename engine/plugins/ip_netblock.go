// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	"github.com/owasp-amass/open-asset-model/relation"
)

type sessnets struct {
	last time.Time
	nets map[string]*oamnet.Netblock
}

type ipNetblock struct {
	name      string
	log       *slog.Logger
	done      chan struct{}
	mlock     sync.Mutex
	netblocks map[string]*sessnets
}

func NewIPNetblock() et.Plugin {
	p := &ipNetblock{
		name:      "IP-Netblock",
		done:      make(chan struct{}, 2),
		netblocks: make(map[string]*sessnets),
	}

	go p.checkNetblocks()
	return p
}

func (d *ipNetblock) Name() string {
	return d.name
}

func (d *ipNetblock) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	name := d.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     d,
		Name:       name,
		Priority:   4,
		Transforms: []string{string(oam.Netblock)},
		EventType:  oam.IPAddress,
		Callback:   d.lookup,
	}); err != nil {
		d.log.Error(fmt.Sprintf("Failed to register a handler: %v", err), "handler", name)
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *ipNetblock) Stop() {
	close(d.done)
	d.log.Info("Plugin stopped")
}

func (d *ipNetblock) lookup(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	var netblock *oamnet.Netblock
	if reserved, cidr := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil
		}

		netblock = &oamnet.Netblock{
			Type: "IPv4",
			CIDR: prefix,
		}
		if prefix.Addr().Is6() {
			netblock.Type = "IPv6"
		}

		d.reservedAS(e, netblock)
	} else {
		var err error

		netblock, err = d.lookupNetblock(e.Session.ID().String(), ip)
		if err != nil {
			netblock, err = support.IPToNetblockWithAttempts(e.Session, ip, 60, time.Second)
			if err != nil {
				return nil
			}
			d.addNetblock(e.Session.ID().String(), netblock)
		}
	}

	if nb, err := e.Session.Cache().CreateAsset(netblock); err == nil && nb != nil {
		_, _ = e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &relation.SimpleRelation{Name: "contains"},
			FromEntity: nb,
			ToEntity:   e.Entity,
		})

		e.Session.Log().Info("relationship discovered", "from",
			netblock.CIDR.String(), "relation", "contains", "to", ip.Address.String(),
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
	}

	return nil
}

func (d *ipNetblock) reservedAS(e *et.Event, netblock *oamnet.Netblock) {
	asn, err := e.Session.Cache().CreateAsset(&oamnet.AutonomousSystem{Number: 0})

	if err == nil && asn != nil {
		autnum, err := e.Session.Cache().CreateAsset(&oamreg.AutnumRecord{
			Number: 0,
			Handle: "AS0",
			Name:   "Reserved Network Address Blocks",
		})

		if err == nil && autnum != nil {
			_, _ = e.Session.Cache().CreateEdge(&dbt.Edge{
				Relation:   &relation.SimpleRelation{Name: "registration"},
				FromEntity: asn,
				ToEntity:   autnum,
			})
		}

		if nb, err := e.Session.Cache().CreateAsset(netblock); err == nil && nb != nil {
			_, _ = e.Session.Cache().CreateEdge(&dbt.Edge{
				Relation:   &relation.SimpleRelation{Name: "announces"},
				FromEntity: asn,
				ToEntity:   nb,
			})
		}
	}
}

func (d *ipNetblock) lookupNetblock(sessid string, ip *oamnet.IPAddress) (*oamnet.Netblock, error) {
	d.mlock.Lock()
	defer d.mlock.Unlock()

	n, ok := d.netblocks[sessid]
	if !ok {
		return nil, errors.New("no netblocks found")
	}
	n.last = time.Now()

	var size int
	var found *oamnet.Netblock
	for _, nb := range n.nets {
		if nb.CIDR.Contains(ip.Address) {
			if s := nb.CIDR.Masked().Bits(); s > size {
				size = s
				found = nb
			}
		}
	}

	if found == nil {
		return nil, errors.New("no netblock match")
	}
	return found, nil
}

func (d *ipNetblock) addNetblock(sessid string, nb *oamnet.Netblock) {
	d.mlock.Lock()
	defer d.mlock.Unlock()

	if _, found := d.netblocks[sessid]; !found {
		d.netblocks[sessid] = &sessnets{nets: make(map[string]*oamnet.Netblock)}
	}

	d.netblocks[sessid].last = time.Now()
	d.netblocks[sessid].nets[nb.CIDR.String()] = nb
}

func (d *ipNetblock) checkNetblocks() {
	t := time.NewTicker(10 * time.Minute)
	defer t.Stop()

	for {
		select {
		case <-d.done:
			return
		case <-t.C:
			d.cleanSessionNetblocks()
		}
	}
}

func (d *ipNetblock) cleanSessionNetblocks() {
	d.mlock.Lock()
	defer d.mlock.Unlock()

	var sessids []string
	for sessid, n := range d.netblocks {
		if time.Since(n.last) > time.Hour {
			sessids = append(sessids, sessid)
		}
	}

	for _, sessid := range sessids {
		delete(d.netblocks, sessid)
	}
}
