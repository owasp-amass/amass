// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/url"
)

type urlexpand struct {
	name       string
	log        *slog.Logger
	transforms []string
	source     *et.Source
}

func NewURLs() et.Plugin {
	return &urlexpand{
		name: "URL-Expansion",
		transforms: []string{
			string(oam.FQDN),
			string(oam.IPAddress),
			string(oam.Service),
			string(oam.File),
		},
		source: &et.Source{
			Name:       "URL-Expansion",
			Confidence: 100,
		},
	}
}

func (u *urlexpand) Name() string {
	return u.name
}

func (u *urlexpand) Start(r et.Registry) error {
	u.log = r.Log().WithGroup("plugin").With("name", u.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       u,
		Name:         u.name,
		Position:     10,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   u.transforms,
		EventType:    oam.URL,
		Callback:     u.check,
	}); err != nil {
		return err
	}

	u.log.Info("Plugin started")
	return nil
}

func (u *urlexpand) Stop() {
	u.log.Info("Plugin stopped")
}

func (u *urlexpand) check(e *et.Event) error {
	oamu, ok := e.Entity.Asset.(*url.URL)
	if !ok {
		return errors.New("failed to extract the URL asset")
	}

	matches, err := e.Session.Config().CheckTransformations(string(oam.URL), append(u.transforms, u.name)...)
	if err != nil || matches.Len() == 0 {
		return nil
	}

	var tstr string
	var inscope bool
	if addr, err := netip.ParseAddr(oamu.Host); err == nil {
		tstr = string(oam.IPAddress)
		if _, conf := e.Session.Scope().IsAssetInScope(&oamnet.IPAddress{Address: addr}, 0); conf > 0 {
			inscope = true
		}
	} else {
		tstr = string(oam.FQDN)
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: oamu.Host}, 0); conf > 0 {
			inscope = true
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.URL), tstr, u.name)
	if err != nil {
		return err
	}

	var findings []*support.Finding
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, u.source, since) {
		if inscope {
			findings = append(findings, u.lookup(e, e.Entity, matches)...)
		}
	} else {
		findings = append(findings, u.store(e, tstr, e.Entity, matches)...)
		support.MarkAssetMonitored(e.Session, e.Entity, u.source)
	}

	if inscope && len(findings) > 0 {
		u.process(e, findings)
	}
	return nil
}

func (u *urlexpand) lookup(e *et.Event, asset *dbt.Entity, m *config.Matches) []*support.Finding {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 60*time.Second)
	defer cancel()

	var findings []*support.Finding
	for _, atype := range u.transforms {
		if !m.IsMatch(atype) {
			continue
		}

		since, err := support.TTLStartTime(e.Session.Config(), string(oam.URL), atype, u.name)
		if err != nil {
			continue
		}

		var label string
		switch atype {
		case string(oam.FQDN):
			label = "domain"
		case string(oam.IPAddress):
			label = "ip_address"
		case string(oam.Service):
			label = "port"
		case string(oam.File):
			label = "file"
		}

		if edges, err := e.Session.DB().OutgoingEdges(ctx, asset, since, label); err == nil && len(edges) > 0 {
			for _, edge := range edges {
				to, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID)
				if err != nil {
					continue
				}

				oamu := asset.Asset.(*url.URL)
				findings = append(findings, &support.Finding{
					From:     asset,
					FromName: "URL: " + oamu.Raw,
					To:       to,
					ToName:   to.Asset.Key(),
					Rel:      edge.Relation,
				})
			}
		}
	}

	return findings
}

func (u *urlexpand) store(e *et.Event, tstr string, asset *dbt.Entity, m *config.Matches) []*support.Finding {
	oamu := asset.Asset.(*url.URL)
	var findings []*support.Finding

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	if tstr == string(oam.FQDN) && m.IsMatch(string(oam.FQDN)) {
		if a, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: oamu.Host}); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "URL: " + oamu.Raw,
				To:       a,
				ToName:   oamu.Host,
				Rel:      &general.SimpleRelation{Name: "domain"},
			})
		}
	} else if ip, err := netip.ParseAddr(oamu.Host); err == nil && m.IsMatch(string(oam.IPAddress)) {
		ntype := "IPv4"
		if ip.Is6() {
			ntype = "IPv6"
		}

		if a, err := e.Session.DB().CreateAsset(ctx, &oamnet.IPAddress{
			Address: ip,
			Type:    ntype,
		}); err == nil && a != nil {
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "URL: " + oamu.Raw,
				To:       a,
				ToName:   ip.String(),
				Rel:      &general.SimpleRelation{Name: "ip_address"},
			})
		}
	}

	return findings
}

func (u *urlexpand) process(e *et.Event, findings []*support.Finding) {
	support.ProcessAssetsWithSource(e, findings, u.source, u.name, u.name+"-Handler")
}
