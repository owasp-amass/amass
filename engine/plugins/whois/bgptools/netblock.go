// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bgptools

import (
	"errors"
	"log/slog"
	"net/netip"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	oam "github.com/owasp-amass/open-asset-model"
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
	ip, ok := e.Asset.Asset.(*oamnet.IPAddress)
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

	src := support.GetSource(e.Session, r.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.IPAddress), string(oam.Netblock), r.plugin.name)
	if err != nil {
		return err
	}

	nb := r.lookup(e, e.Asset, since)
	if nb == nil {
		nb = r.query(e, e.Asset, src)
	}

	if nb != nil {
		r.process(e, e.Asset, nb, src)
	}
	return nil
}

func (r *netblock) lookup(e *et.Event, ip *dbt.Asset, since time.Time) *dbt.Asset {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		sincestr := since.Format("2006-01-02 15:04:05")
		from := "((((assets as ip inner join relations as contains on ip.id = contains.to_asset_id) "
		from2 := "inner join assets on contains.from_asset_id = assets.id) "
		from3 := "inner join relations on relations.from_asset_id = assets.id) "
		from4 := "inner join assets as srcs on relations.to_asset_id = srcs.id) "
		where := "where ip.type = '" + string(oam.IPAddress) + "' and assets.type = '"
		where2 := string(oam.Netblock) + "' and contains.type = 'contains' "
		where3 := "and contains.last_seen > '" + sincestr + "' and ip.id = " + ip.ID
		where4 := " and relations.type = 'source' and relations.last_seen > '" + sincestr + "'"
		where5 := " and srcs.type = 'Source' and srcs.content->>'name' = '" + r.plugin.name + "'"

		var nb *dbt.Asset
		query := from + from2 + from3 + from4 + where + where2 + where3 + where4 + where5
		if assets, err := e.Session.DB().AssetQuery(query); err == nil && len(assets) > 0 {
			nb = assets[0]
		}
		done <- nb
	})

	return <-done
}

func (r *netblock) query(e *et.Event, ip, src *dbt.Asset) *dbt.Asset {
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

func (r *netblock) store(e *et.Event, cidr netip.Prefix, ip, src *dbt.Asset) *dbt.Asset {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	ntype := "IPv4"
	if cidr.Addr().Is6() {
		ntype = "IPv6"
	}

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		nb, err := e.Session.DB().Create(nil, "", &oamnet.Netblock{
			CIDR: cidr,
			Type: ntype,
		})
		if err == nil && nb != nil {
			_, _ = e.Session.DB().Link(nb, "contains", ip)
			_, _ = e.Session.DB().Link(nb, "source", src)
		}

		done <- nb
	})

	return <-done
}

func (r *netblock) process(e *et.Event, ip, nb, src *dbt.Asset) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Asset:   nb,
		Session: e.Session,
	})

	if a, hit := e.Session.Cache().GetAsset(nb.Asset); hit && a != nil {
		now := time.Now()

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "contains",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a,
			ToAsset:   ip,
		})

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a,
			ToAsset:   src,
		})

		e.Session.Log().Info("relationship discovered", "from", nb.Asset.Key(), "relation",
			"contains", "to", ip.Asset.Key(), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
	}
}
