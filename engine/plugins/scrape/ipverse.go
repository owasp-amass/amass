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

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/owasp-amass/open-asset-model/relation"
	"go.uber.org/ratelimit"
)

type ipverse struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewIPVerse() et.Plugin {
	return &ipverse{
		name:   "GitHub-IPVerse",
		fmtstr: "https://raw.githubusercontent.com/ipverse/asn-ip/master/as/%d/aggregated.json",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
		source: &et.Source{
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
	_, ok := e.Entity.Asset.(*oamnet.AutonomousSystem)
	if !ok {
		return errors.New("failed to extract the AutonomousSystem asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.AutonomousSystem), string(oam.Netblock), v.name)
	if err != nil {
		return err
	}

	src := v.source
	var cidrs []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		cidrs = append(cidrs, v.lookup(e, e.Entity, since, src)...)
	} else {
		cidrs = append(cidrs, v.query(e, e.Entity, src)...)
		support.MarkAssetMonitored(e.Session, e.Entity, src)
	}

	for _, cidr := range cidrs {
		v.process(e, e.Entity, cidr)
	}
	return nil
}

func (v *ipverse) lookup(e *et.Event, as *dbt.Entity, since time.Time, src *et.Source) []*dbt.Entity {
	edges, err := e.Session.Cache().OutgoingEdges(as, since, "announces")
	if err != nil {
		return nil
	}

	for _, edge := range edges {
		if tags, err := e.Session.Cache().GetEdgeTags(edge, since, src.Name); err == nil && len(tags) > 0 {
			for _, tag := range tags {
				if _, ok := tag.Property.(*property.SourceProperty); ok {
					if nb, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && as != nil {
						return nb
					}
				}
			}
		}
	}
	return nil
}

func (v *ipverse) query(e *et.Event, asset *dbt.Entity, src *et.Source) []*dbt.Entity {
	v.rlimit.Take()

	as := asset.Asset.(*oamnet.AutonomousSystem)
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(v.fmtstr, as.Number)})
	if err != nil || resp.Body == "" {
		return nil
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
		return nil
	}

	var cidrs []netip.Prefix
	for _, ip := range append(result.CIDRs.IPv4, result.CIDRs.IPv6...) {
		if cidr, err := netip.ParsePrefix(ip); err == nil {
			cidrs = append(cidrs, cidr)
		}
	}

	return v.store(e, cidrs, asset, src)
}

func (v *ipverse) store(e *et.Event, cidrs []netip.Prefix, as *dbt.Entity, src *et.Source) []*dbt.Entity {
	var results []*dbt.Entity

	for _, cidr := range cidrs {
		ntype := "IPv4"
		if cidr.Addr().Is6() {
			ntype = "IPv6"
		}

		if nb, err := e.Session.Cache().CreateAsset(&oamnet.Netblock{
			CIDR: cidr,
			Type: ntype,
		}); err == nil && nb != nil {
			results = append(results, nb)

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
	}

	return results
}

func (v *ipverse) process(e *et.Event, as, nb *dbt.Entity) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    nb.Asset.Key(),
		Asset:   nb,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", as.Asset.Key(), "relation",
		"announces", "to", nb.Asset.Key(), slog.Group("plugin", "name", v.name, "handler", v.name+"-Handler"))
}
