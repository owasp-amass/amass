// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type autsys struct {
	sync.Mutex
	name   string
	plugin *bgpTools
}

func (r *autsys) Name() string {
	return r.name
}

func (r *autsys) check(e *et.Event) error {
	nb, valid := e.Entity.Asset.(*oamnet.Netblock)
	if !valid {
		return errors.New("failed to extract the Netblock asset")
	}

	ipstr := nb.CIDR.Addr().String()
	if reserved, _ := amassnet.IsReservedAddress(ipstr); reserved {
		return nil
	}

	cidr := nb.Key()
	_, ipnet, _ := net.ParseCIDR(cidr)
	if ipnet == nil {
		return nil
	}

	first, _ := amassnet.FirstLast(ipnet)
	if first == nil {
		return nil
	}

	// check if there's a autonomous system associated with this netblock
	if asn, src := r.checkCIDRanger(e, cidr, first); asn != 0 {
		if asent := r.store(e, asn, e.Entity, src); asent != nil {
			r.process(e, e.Entity, asent)
			return nil
		}
	}

	r.Lock()
	defer r.Unlock()

	// re-check if there's a autonomous system associated with this netblock
	if asn, src := r.checkCIDRanger(e, cidr, first); asn != 0 {
		if asent := r.store(e, asn, e.Entity, src); asent != nil {
			r.process(e, e.Entity, asent)
			return nil
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Netblock), string(oam.AutonomousSystem), r.plugin.name)
	if err != nil {
		return err
	}

	as := r.lookup(e, e.Entity, since)
	if as == nil {
		as = r.query(e, e.Entity)
	}

	if as != nil {
		r.process(e, e.Entity, as)
	}
	return nil
}

func (r *autsys) lookup(e *et.Event, nb *dbt.Entity, since time.Time) *dbt.Entity {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	edges, err := e.Session.DB().IncomingEdges(ctx, nb, since, "announces")
	if err != nil {
		return nil
	}

	for _, edge := range edges {
		if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, r.plugin.source.Name); err == nil && len(tags) > 0 {
			for _, tag := range tags {
				if _, ok := tag.Property.(*general.SourceProperty); ok {
					if as, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && as != nil {
						return as
					}
				}
			}
		}
	}
	return nil
}

func (r *autsys) query(e *et.Event, nb *dbt.Entity) *dbt.Entity {
	var asn int
	arg := nb.Asset.Key()

	if record, err := r.plugin.whois(arg); err == nil {
		asn = record.ASN
	} else {
		e.Session.Log().Error("failed to obtain a response from the WHOIS server", "err",
			err.Error(), "argument", arg, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
	}

	if asn == 0 {
		return nil
	}
	return r.store(e, asn, nb, r.plugin.source)
}

func (r *autsys) checkCIDRanger(e *et.Event, cidr string, ip net.IP) (int, *et.Source) {
	var asn int
	var src *et.Source

	if entries, err := e.Session.CIDRanger().ContainingNetworks(ip); err == nil && len(entries) > 0 {
		for _, entry := range entries {
			if arentry, ok := entry.(*sessions.CIDRangerEntry); ok {
				if strings.EqualFold(cidr, arentry.Net.String()) {
					asn = arentry.ASN
					src = arentry.Src
					break
				}
			}
		}
	}

	return asn, src
}

func (r *autsys) store(e *et.Event, asn int, nb *dbt.Entity, src *et.Source) *dbt.Entity {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	as, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: asn})
	if err == nil && as != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, as, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})

		if edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "announces"},
			FromEntity: as,
			ToEntity:   nb,
		}); err == nil && edge != nil {
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
				Source:     r.plugin.source.Name,
				Confidence: r.plugin.source.Confidence,
			})
		}
	}
	return as
}

func (r *autsys) process(e *et.Event, nb, as *dbt.Entity) {
	asname := "AS" + as.Asset.Key()

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    asname,
		Entity:  as,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", asname, "relation", "announces",
		"to", nb.Asset.Key(), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
}
