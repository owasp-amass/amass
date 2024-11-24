// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/owasp-amass/open-asset-model/relation"
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
	// check if there's a netblock and autonomous system associated with this IP address
	if _, err := support.IPToNetblock(e.Session, ip); err == nil {
		// the rest of the work will be done further down the pipeline
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.IPAddress), string(oam.Netblock), r.plugin.name)
	if err != nil {
		return err
	}

	src := r.plugin.source
	nb := r.lookup(e, e.Entity, since, src)
	if nb == nil {
		nb = r.query(e, e.Entity, src)
	}

	if nb != nil {
		r.process(e, e.Asset, nb)
	}
	return nil
}

func (r *netblock) lookup(e *et.Event, ip *dbt.Entity, since time.Time, src *et.Source) *dbt.Entity {
	addr, ok := ip.Asset.(*oamnet.IPAddress)
	if !ok {
		return nil
	}

	edges, err := e.Session.Cache().IncomingEdges(ip, since, "contains")
	if err != nil {
		return nil
	}

	var size int
	var nb *dbt.Entity
	var target *dbt.Edge
	for _, edge := range edges {
		entity, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID)
		if err != nil {
			continue
		}
		if tmp, ok := entity.Asset.(*oamnet.Netblock); ok && tmp.CIDR.Contains(addr.Address) {
			if s := tmp.CIDR.Masked().Bits(); s > size {
				size = s
				nb = tmp
				target = edge
			}
		}
	}
	if target == nil {
		return nil
	}

	if tags, err := e.Session.Cache().GetEdgeTags(target, since, src.Name); err == nil && len(tags) > 0 {
		for _, tag := range tags {
			if _, ok := tag.Property.(*property.SourceProperty); ok {
				return nb
			}
		}
	}
	return nil
}

func (r *netblock) query(e *et.Event, ip *dbt.Entity, src *et.Source) *dbt.Entity {
	var asn, most int
	var cidr netip.Prefix

	r.plugin.Lock()
	a := ip.Asset.(*oamnet.IPAddress)
	for num, anouncements := range r.plugin.data {
		for _, prefix := range anouncements {
			// Select the smallest CIDR
			if bits := prefix.Masked().Bits(); most < bits && prefix.Contains(a.Address) {
				asn = num
				most = bits
				cidr = prefix
			}
		}
	}
	r.plugin.Unlock()

	if asn == 0 {
		if record, err := r.plugin.whois(a.Address.String()); err == nil {
			asn = record.ASN
			cidr = record.Prefix

			r.plugin.Lock()
			r.plugin.data[asn] = append(r.plugin.data[asn], record.Prefix)
			r.plugin.Unlock()
		}
	}

	if asn == 0 {
		return nil
	}
	return r.store(e, cidr, ip, src)
}

func (r *netblock) store(e *et.Event, cidr netip.Prefix, ip *dbt.Entity, src *et.Source) *dbt.Entity {
	ntype := "IPv4"
	if cidr.Addr().Is6() {
		ntype = "IPv6"
	}

	nb, err := e.Session.DB().Create(nil, "", &oamnet.Netblock{
		CIDR: cidr,
		Type: ntype,
	})
	if err == nil && nb != nil {
		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &relation.SimpleRelation{Name: "contains"},
			FromEntity: nb,
			ToEntity:   ip,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		}
	}

	return nb
}

func (r *netblock) process(e *et.Event, ip, nb *dbt.Entity) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Asset:   nb,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", nb.Asset.Key(), "relation",
		"contains", "to", ip.Asset.Key(), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
}
