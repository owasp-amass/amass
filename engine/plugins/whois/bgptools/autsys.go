// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"errors"
	"log/slog"
	"sync"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	oam "github.com/owasp-amass/open-asset-model"
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
	nb, ok := e.Asset.Asset.(*oamnet.Netblock)
	if !ok {
		return errors.New("failed to extract the Netblock asset")
	}

	ipstr := nb.CIDR.Addr().String()
	if reserved, _ := amassnet.IsReservedAddress(ipstr); reserved {
		return nil
	}
	// check if there's an autonomous system associated with this netblock
	if relations, hit := e.Session.Cache().GetRelations(&dbt.Relation{
		Type:    "announces",
		ToAsset: e.Asset,
	}); hit && len(relations) > 0 {
		// the rest of the work will be done further down the pipeline
		return nil
	}

	src := support.GetSource(e.Session, r.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Netblock), string(oam.AutonomousSystem), r.plugin.name)
	if err != nil {
		return err
	}

	as := r.lookup(e, e.Asset, since)
	if as == nil {
		as = r.query(e, e.Asset, src)
	}

	if as != nil {
		r.process(e, e.Asset, as, src)
	}
	return nil
}

func (r *autsys) lookup(e *et.Event, nb *dbt.Asset, since time.Time) *dbt.Asset {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		sincestr := since.Format("2006-01-02 15:04:05")
		from := "((((assets as nb inner join relations as announces on nb.id = announces.to_asset_id) "
		from2 := "inner join assets on announces.from_asset_id = assets.id) "
		from3 := "inner join relations on relations.from_asset_id = assets.id) "
		from4 := "inner join assets as srcs on relations.to_asset_id = srcs.id) "
		where := "where nb.type = '" + string(oam.Netblock) + "' and assets.type = '"
		where2 := string(oam.AutonomousSystem) + "' and announces.type = 'announces' "
		where3 := "and announces.last_seen > '" + sincestr + "' and nb.id = " + nb.ID
		where4 := " and relations.type = 'source' and relations.last_seen > '" + sincestr + "'"
		where5 := " and srcs.type = 'Source' and srcs.content->>'name' = '" + r.plugin.name + "'"

		var as *dbt.Asset
		query := from + from2 + from3 + from4 + where + where2 + where3 + where4 + where5
		if assets, err := e.Session.DB().AssetQuery(query); err == nil && len(assets) > 0 {
			as = assets[0]
		}
		done <- as
	})

	return <-done
}

func (r *autsys) query(e *et.Event, nb, src *dbt.Asset) *dbt.Asset {
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

func (r *autsys) store(e *et.Event, asn int, nb, src *dbt.Asset) *dbt.Asset {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		as, err := e.Session.DB().Create(nil, "", &oamnet.AutonomousSystem{Number: asn})
		if err == nil && as != nil {
			_, _ = e.Session.DB().Link(as, "announces", nb)
			_, _ = e.Session.DB().Link(as, "source", src)
		}

		done <- as
	})

	return <-done
}

func (r *autsys) process(e *et.Event, nb, as, src *dbt.Asset) {
	asname := "AS" + as.Asset.Key()
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    asname,
		Asset:   as,
		Session: e.Session,
	})

	if a, hit := e.Session.Cache().GetAsset(as.Asset); hit && a != nil {
		now := time.Now()

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "announces",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a,
			ToAsset:   nb,
		})

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a,
			ToAsset:   src,
		})

		e.Session.Log().Info("relationship discovered",
			"from", asname, "relation", "announces", "to", nb.Asset.Key(),
			slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
	}
}
