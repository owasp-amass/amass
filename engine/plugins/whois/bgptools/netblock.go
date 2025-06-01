// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	"github.com/owasp-amass/amass/v4/engine/sessions"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type netblock struct {
	name   string
	plugin *bgpTools
}

func (r *netblock) Name() string {
	return r.name
}

func (r *netblock) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	ipstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(ipstr); reserved {
		return nil
	}
	// check if there's a netblock associated with this IP address
	if found, err := e.Session.CIDRanger().Contains(net.ParseIP(ipstr)); err == nil && found {
		// the rest of the work will be done further down the pipeline
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.IPAddress), string(oam.Netblock), r.plugin.name)
	if err != nil {
		return err
	}

	nb, as := r.lookup(e, e.Entity, since)
	if nb == nil || as == nil {
		nb, as = r.query(e, e.Entity)
	}

	if nb != nil && as != nil {
		if asnent, ok := as.Asset.(*oamnet.AutonomousSystem); ok {
			if _, ipnet, err := net.ParseCIDR(nb.Asset.(*oamnet.Netblock).CIDR.String()); err == nil && ipnet != nil {
				_ = e.Session.CIDRanger().Insert(&sessions.CIDRangerEntry{
					Net: ipnet,
					ASN: asnent.Number,
					Src: r.plugin.source,
				})
			}

			r.process(e, e.Entity, nb, as)
		}
	}
	return nil
}

func (r *netblock) lookup(e *et.Event, ip *dbt.Entity, since time.Time) (*dbt.Entity, *dbt.Entity) {
	addr, ok := ip.Asset.(*oamnet.IPAddress)
	if !ok {
		return nil, nil
	}

	edges, err := e.Session.Cache().IncomingEdges(ip, since, "contains")
	if err != nil {
		return nil, nil
	}

	var size int
	var nb *dbt.Entity
	for _, edge := range edges {
		entity, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID)
		if err != nil {
			continue
		}
		if tmp, ok := entity.Asset.(*oamnet.Netblock); ok && tmp.CIDR.Contains(addr.Address) {
			if s := tmp.CIDR.Masked().Bits(); s > size {
				var found bool

				if tags, err := e.Session.Cache().GetEdgeTags(edge, since, r.plugin.source.Name); err == nil && len(tags) > 0 {
					for _, tag := range tags {
						if _, ok := tag.Property.(*general.SourceProperty); ok {
							found = true
							break
						}
					}
				}

				if found {
					size = s
					nb = entity
				}
			}
		}
	}

	var found bool
	var asent *dbt.Entity
	if nb != nil {
		edges, err := e.Session.Cache().IncomingEdges(nb, since, "announces")
		if err == nil && len(edges) > 0 {
			for _, edge := range edges {
				asent, err = e.Session.Cache().FindEntityById(edge.FromEntity.ID)

				if err == nil && asent != nil {
					found = true
					break
				}
			}
		}
	}
	if !found {
		return nil, nil
	}

	return nb, asent
}

func (r *netblock) query(e *et.Event, ent *dbt.Entity) (*dbt.Entity, *dbt.Entity) {
	ip := ent.Asset.(*oamnet.IPAddress)
	addrstr := ip.Address.String()

	record, err := r.plugin.whois(addrstr)
	if err != nil || record == nil {
		e.Session.Log().Error("failed to obtain a response from the WHOIS server", "err",
			err.Error(), "argument", addrstr, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
		return nil, nil
	}

	return r.store(e, record.Prefix, ent, record.ASN)
}

func (r *netblock) store(e *et.Event, cidr netip.Prefix, ip *dbt.Entity, asn int) (*dbt.Entity, *dbt.Entity) {
	ntype := "IPv4"
	if cidr.Addr().Is6() {
		ntype = "IPv6"
	}

	nb, err := e.Session.Cache().CreateAsset(&oamnet.Netblock{
		CIDR: cidr,
		Type: ntype,
	})

	if err != nil || nb == nil {
		return nil, nil
	}

	_, _ = e.Session.Cache().CreateEntityProperty(nb, &general.SourceProperty{
		Source:     r.plugin.source.Name,
		Confidence: r.plugin.source.Confidence,
	})

	edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "contains"},
		FromEntity: nb,
		ToEntity:   ip,
	})
	if err != nil || edge == nil {
		return nil, nil
	}

	_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     r.plugin.source.Name,
		Confidence: r.plugin.source.Confidence,
	})

	as, err := e.Session.Cache().CreateAsset(&oamnet.AutonomousSystem{Number: asn})
	if err != nil || as == nil {
		return nil, nil
	}

	_, _ = e.Session.Cache().CreateEntityProperty(as, &general.SourceProperty{
		Source:     r.plugin.source.Name,
		Confidence: r.plugin.source.Confidence,
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
		Source:     r.plugin.source.Name,
		Confidence: r.plugin.source.Confidence,
	})

	return nb, as
}

func (r *netblock) process(e *et.Event, ip, nb, as *dbt.Entity) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Entity:  nb,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", nb.Asset.Key(), "relation",
		"contains", "to", ip.Asset.Key(), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))

	asname := "AS" + as.Asset.Key()
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    asname,
		Entity:  as,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", asname, "relation", "announces",
		"to", nb.Asset.Key(), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
}
