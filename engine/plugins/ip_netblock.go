// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"errors"
	"fmt"
	"log/slog"
	"net/netip"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	"github.com/owasp-amass/amass/v4/engine/sessions"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type ipNetblock struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewIPNetblock() et.Plugin {
	return &ipNetblock{
		name: "IP-Netblock",
		source: &et.Source{
			Name:       "IP-Netblock",
			Confidence: 100,
		},
	}
}

func (d *ipNetblock) Name() string {
	return d.name
}

func (d *ipNetblock) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	name := d.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         name,
		Priority:     4,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.Netblock)},
		EventType:    oam.IPAddress,
		Callback:     d.lookup,
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

func (d *ipNetblock) lookup(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	if reserved, cidr := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil
		}

		netblock := &oamnet.Netblock{
			Type: "IPv4",
			CIDR: prefix,
		}
		if prefix.Addr().Is6() {
			netblock.Type = "IPv6"
		}

		d.reservedAS(e, netblock)
		return nil
	}

	entry := support.IPNetblock(e.Session, ip.Address.String())
	if entry == nil {
		return nil
	}

	nb, as := d.store(e, entry)
	if nb == nil || as == nil {
		return nil
	}

	d.process(e, e.Entity, nb, as)
	return nil
}

func (d *ipNetblock) store(e *et.Event, entry *sessions.CIDRangerEntry) (*dbt.Entity, *dbt.Entity) {
	netblock := &oamnet.Netblock{
		Type: "IPv4",
		CIDR: netip.MustParsePrefix(entry.Net.String()),
	}
	if netblock.CIDR.Addr().Is6() {
		netblock.Type = "IPv6"
	}

	nb, err := e.Session.Cache().CreateAsset(netblock)
	if err != nil || nb == nil {
		return nil, nil
	}

	_, _ = e.Session.Cache().CreateEntityProperty(nb, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "contains"},
		FromEntity: nb,
		ToEntity:   e.Entity,
	})
	if err != nil || edge == nil {
		return nil, nil
	}

	_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	as, err := e.Session.Cache().CreateAsset(&oamnet.AutonomousSystem{Number: entry.ASN})
	if err != nil || as == nil {
		return nil, nil
	}

	_, _ = e.Session.Cache().CreateEntityProperty(as, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	edge, err = e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "announces"},
		FromEntity: as,
		ToEntity:   nb,
	})
	if err != nil || edge == nil {
		return nil, nil
	}

	_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     entry.Src.Name,
		Confidence: entry.Src.Confidence,
	})

	return nb, as
}

func (d *ipNetblock) process(e *et.Event, ip, nb, as *dbt.Entity) {
	ipstr := ip.Asset.Key()
	nbname := nb.Asset.Key()

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Entity:  nb,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", nbname, "relation", "contains",
		"to", ipstr, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))

	asname := "AS" + as.Asset.Key()
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    asname,
		Entity:  as,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", asname, "relation", "announces",
		"to", nbname, slog.Group("plugin", "name", d.name, "handler", d.name+"-Handler"))
}

func (d *ipNetblock) reservedAS(e *et.Event, netblock *oamnet.Netblock) {
	nb, err := e.Session.Cache().CreateAsset(netblock)
	if err != nil || nb == nil {
		return
	}

	_, _ = e.Session.Cache().CreateEntityProperty(nb, &general.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})

	asn, err := e.Session.Cache().CreateAsset(&oamnet.AutonomousSystem{Number: 0})
	if err != nil || asn == nil {
		return
	}

	_, _ = e.Session.Cache().CreateEntityProperty(nb, &general.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})

	autnum, err := e.Session.Cache().CreateAsset(&oamreg.AutnumRecord{
		Number: 0,
		Handle: "AS0",
		Name:   "Reserved Network Address Blocks",
	})
	if err != nil || autnum == nil {
		return
	}

	edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "registration"},
		FromEntity: asn,
		ToEntity:   autnum,
	})
	if err != nil || edge == nil {
		return
	}

	_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})

	edge, err = e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "announces"},
		FromEntity: asn,
		ToEntity:   nb,
	})
	if err != nil || edge == nil {
		return
	}

	_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     d.source.Name,
		Confidence: d.source.Confidence,
	})
}
