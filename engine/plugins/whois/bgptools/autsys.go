// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"errors"
	"log/slog"
	"sync"
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

type autsys struct {
	sync.Mutex
	name   string
	plugin *bgpTools
}

func (r *autsys) Name() string {
	return r.name
}

func (r *autsys) check(e *et.Event) error {
	nb, ok := e.Entity.Asset.(*oamnet.Netblock)
	if !ok {
		return errors.New("failed to extract the Netblock asset")
	}

	ipstr := nb.CIDR.Addr().String()
	if reserved, _ := amassnet.IsReservedAddress(ipstr); reserved {
		return nil
	}
	// check if there's an autonomous system associated with this netblock
	if edges, err := e.Session.Cache().IncomingEdges(e.Entity, e.Session.Cache().StartTime(), "announces"); err == nil && len(edges) > 0 {
		// the rest of the work will be done further down the pipeline
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Netblock), string(oam.AutonomousSystem), r.plugin.name)
	if err != nil {
		return err
	}

	src := r.plugin.source
	as := r.lookup(e, e.Entity, since, src)
	if as == nil {
		as = r.query(e, e.Entity, src)
	}

	if as != nil {
		r.process(e, e.Asset, as)
	}
	return nil
}

func (r *autsys) lookup(e *et.Event, nb *dbt.Entity, since time.Time, src *et.Source) *dbt.Entity {
	edges, err := e.Session.Cache().IncomingEdges(nb, since, "announces")
	if err != nil {
		return nil
	}

	for _, edge := range edges {
		if tags, err := e.Session.Cache().GetEdgeTags(edge, since, src.Name); err == nil && len(tags) > 0 {
			for _, tag := range tags {
				if _, ok := tag.Property.(*property.SourceProperty); ok {
					if as, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && as != nil {
						return as
					}
				}
			}
		}
	}
	return nil
}

func (r *autsys) query(e *et.Event, nb *dbt.Entity, src *et.Source) *dbt.Entity {
	var asn int

	r.plugin.Lock()
	cidr := nb.Asset.Key()
	for num, anouncements := range r.plugin.data {
		for _, prefix := range anouncements {
			if prefix.String() == cidr {
				asn = num
				break
			}
		}
	}
	r.plugin.Unlock()

	if asn == 0 {
		if record, err := r.plugin.whois(nb.Asset.Key()); err == nil {
			asn = record.ASN

			r.plugin.Lock()
			r.plugin.data[asn] = append(r.plugin.data[asn], record.Prefix)
			r.plugin.Unlock()
		}
	}

	if asn == 0 {
		return nil
	}
	return r.store(e, asn, nb, src)
}

func (r *autsys) store(e *et.Event, asn int, nb *dbt.Entity, src *et.Source) *dbt.Entity {
	as, err := e.Session.Cache().CreateAsset(&oamnet.AutonomousSystem{Number: asn})
	if err == nil && as != nil {
		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &relation.SimpleRelation{Name: "announces"},
			FromEntity: as,
			ToEntity:   nb,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
				Source:     src.Name,
				Confidence: src.Confidence,
			})
		}
	}
	return as
}

func (r *autsys) process(e *et.Event, nb, as *dbt.Entity) {
	asname := "AS" + as.Asset.Key()
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    asname,
		Asset:   as,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", asname, "relation", "announces",
		"to", nb.Asset.Key(), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
}
