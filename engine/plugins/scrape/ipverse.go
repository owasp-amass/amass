// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"time"

	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/source"
	"go.uber.org/ratelimit"
)

type ipverse struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *source.Source
}

func NewIPVerse() et.Plugin {
	return &ipverse{
		name:   "GitHub-IPVerse",
		fmtstr: "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%d/aggregated.json",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
		source: &source.Source{
			Name:       "GitHub-IPVerse",
			Confidence: 90,
		},
	}
}

func (v *ipverse) Name() string {
	return v.name
}

func (v *ipverse) Start(r et.Registry) error {
	v.log = r.Log().WithGroup("plugin").With("name", v.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     v,
		Name:       v.name + "-Handler",
		Priority:   1,
		Transforms: []string{string(oam.Netblock)},
		EventType:  oam.AutonomousSystem,
		Callback:   v.check,
	}); err != nil {
		return err
	}

	v.log.Info("Plugin started")
	return nil
}

func (v *ipverse) Stop() {
	v.log.Info("Plugin stopped")
}

func (v *ipverse) check(e *et.Event) error {
	_, ok := e.Asset.Asset.(*oamnet.AutonomousSystem)
	if !ok {
		return errors.New("failed to extract the AutonomousSystem asset")
	}

	src := support.GetSource(e.Session, v.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.AutonomousSystem), string(oam.Netblock), v.name)
	if err != nil {
		return err
	}

	var cidrs []*dbt.Asset
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		cidrs = append(cidrs, v.lookup(e, e.Asset, since)...)
	} else {
		cidrs = append(cidrs, v.query(e, e.Asset, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	for _, cidr := range cidrs {
		v.process(e, e.Asset, cidr, src)
	}
	return nil
}

func (v *ipverse) lookup(e *et.Event, as *dbt.Asset, since time.Time) []*dbt.Asset {
	done := make(chan struct{}, 1)
	defer close(done)

	var assets []*dbt.Asset
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		sincestr := since.Format("2006-01-02 15:04:05")
		from := "((((assets as asns inner join relations as ann on asns.id = ann.from_asset_id) "
		from2 := "inner join assets on ann.to_asset_id = assets.id) "
		from3 := "inner join relations on relations.from_asset_id = assets.id) "
		from4 := "inner join assets as srcs on relations.to_asset_id = srcs.id) "
		where := "where asns.type = '" + string(oam.AutonomousSystem) + "' and assets.type = '"
		where2 := string(oam.Netblock) + "' and ann.type = 'announces' "
		where3 := "and ann.last_seen > '" + sincestr + "' and asns.id = " + as.ID
		where4 := " and relations.type = 'source' and relations.last_seen > '" + sincestr + "'"
		where5 := " and srcs.type = 'Source' and srcs.content->>'name' = '" + v.name + "'"

		query := from + from2 + from3 + from4 + where + where2 + where3 + where4 + where5
		if results, err := e.Session.DB().AssetQuery(query); err == nil && len(assets) > 0 {
			assets = append(assets, results...)
		}
	})
	<-done
	return assets
}

func (v *ipverse) query(e *et.Event, asset, src *dbt.Asset) []*dbt.Asset {
	v.rlimit.Take()

	as := asset.Asset.(*oamnet.AutonomousSystem)
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(v.fmtstr, as.Number)})
	if err != nil || resp.Body == "" {
		return []*dbt.Asset{}
	}

	type record struct {
		ASN   int `json:"asn"`
		CIDRs struct {
			IPv4 []string `json:"ipv4"`
			IPv6 []string `json:"ipv6"`
		} `json:"subnets"`
	}

	var result record
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return []*dbt.Asset{}
	}

	var cidrs []netip.Prefix
	for _, ip := range append(result.CIDRs.IPv4, result.CIDRs.IPv6...) {
		if cidr, err := netip.ParsePrefix(ip); err == nil {
			cidrs = append(cidrs, cidr)
		}
	}

	return v.store(e, cidrs, asset, src)
}

func (v *ipverse) store(e *et.Event, cidrs []netip.Prefix, as, src *dbt.Asset) []*dbt.Asset {
	done := make(chan struct{}, 1)
	defer close(done)

	var assets []*dbt.Asset
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		for _, cidr := range cidrs {
			ntype := "IPv4"
			if cidr.Addr().Is6() {
				ntype = "IPv6"
			}

			if nb, err := e.Session.DB().Create(as, "announces", &oamnet.Netblock{
				CIDR: cidr,
				Type: ntype,
			}); err == nil && nb != nil {
				assets = append(assets, nb)
				_, _ = e.Session.DB().Link(nb, "source", src)
			}
		}

	})
	<-done
	return assets
}

func (v *ipverse) process(e *et.Event, as, nb, src *dbt.Asset) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Asset:   nb,
		Session: e.Session,
	})

	if a, hit := e.Session.Cache().GetAsset(nb.Asset); hit && a != nil {
		now := time.Now()

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "announces",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: as,
			ToAsset:   a,
		})
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a,
			ToAsset:   src,
		})
		e.Session.Log().Info("relationship discovered", "from", as.Asset.Key(), "relation",
			"announces", "to", nb.Asset.Key(), slog.Group("plugin", "name", v.name, "handler", v.name+"-Handler"))
	}
}
