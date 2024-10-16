// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type ipNetblock struct {
	name string
	log  *slog.Logger
}

func NewIPNetblock() et.Plugin {
	return &ipNetblock{name: "IP-Netblock"}
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
	d.log.Info("Plugin stopped")
}

// ipLookup function queries the bgptools whois server using an
// IP address to retrieve related ASN, netblock, and RIR details.
func (d *ipNetblock) lookup(e *et.Event) error {
	ip, ok := e.Asset.Asset.(*oamnet.IPAddress)
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

		netblock, err = support.IPToNetblockWithAttempts(e.Session, ip, 60, time.Second)
		if err != nil {
			return nil
		}
	}

	var a, nb *dbt.Asset
	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		var err error
		nb, err = e.Session.DB().Create(nil, "", netblock)
		if err == nil {
			a, _ = e.Session.DB().Create(nb, "contains", ip)
		}
	})
	<-done
	close(done)

	if a != nil && nb != nil {
		now := time.Now()

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "contains",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: nb,
			ToAsset:   a,
		})

		e.Session.Log().Info("relationship discovered", "from",
			netblock.CIDR.String(), "relation", "contains", "to", ip.Address.String(),
			slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
	}
	return nil
}

func (d *ipNetblock) reservedAS(e *et.Event, netblock *oamnet.Netblock) {
	now := time.Now()
	group := slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler")

	var asn, autnum, nb *dbt.Asset
	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		var err error
		asn, err = e.Session.DB().Create(nil, "", &oamnet.AutonomousSystem{Number: 0})
		if err == nil && asn != nil {
			autnum, _ = e.Session.DB().Create(asn, "registration", &oamreg.AutnumRecord{
				Number: 0,
				Handle: "AS0",
				Name:   "Reserved Network Address Blocks",
			})
			nb, _ = e.Session.DB().Create(asn, "announces", netblock)
		}
	})
	<-done
	close(done)

	if asn == nil || autnum == nil {
		return
	}

	e.Session.Cache().SetAsset(asn)
	e.Session.Cache().SetAsset(autnum)
	e.Session.Cache().SetRelation(&dbt.Relation{
		Type:      "registration",
		CreatedAt: now,
		LastSeen:  now,
		FromAsset: asn,
		ToAsset:   autnum,
	})

	e.Session.Log().Info("relationship discovered", "from", 0, "relation",
		"registration", "to", "Reserved Network Address Blocks", group)

	if nb != nil {
		e.Session.Cache().SetAsset(nb)
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "announces",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: asn,
			ToAsset:   nb,
		})

		e.Session.Log().Info("relationship discovered", "from", 0,
			"relation", "announces", "to", netblock.CIDR.String(), group)
	}
}
