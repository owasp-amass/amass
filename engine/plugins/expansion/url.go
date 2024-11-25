// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package expansion

import (
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/config"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
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
		Plugin:     u,
		Name:       u.name,
		Transforms: u.transforms,
		EventType:  oam.URL,
		Callback:   u.check,
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
		if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: oamu.Host}, 0); conf > 0 {
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
		findings = append(findings, u.store(e, tstr, e.Entity, u.source, matches)...)
		support.MarkAssetMonitored(e.Session, e.Entity, u.source)
	}

	if inscope && len(findings) > 0 {
		u.process(e, findings, u.source)
	}
	return nil
}

func (u *urlexpand) lookup(e *et.Event, asset *dbt.Entity, m *config.Matches) []*support.Finding {
	rtypes := stringset.New()
	defer rtypes.Close()

	var findings []*support.Finding
	sinces := make(map[string]time.Time)
	for _, atype := range u.transforms {
		if !m.IsMatch(atype) {
			continue
		}

		since, err := support.TTLStartTime(e.Session.Config(), string(oam.URL), atype, u.name)
		if err != nil {
			continue
		}
		sinces[atype] = since

		switch atype {
		case string(oam.FQDN):
			rtypes.Insert("domain")
		case string(oam.IPAddress):
			rtypes.Insert("ip_address")
		case string(oam.Service):
			rtypes.Insert("port")
		case string(oam.File):
			rtypes.Insert("file")
		}
	}

	if edges, err := e.Session.Cache().OutgoingEdges(asset, time.Time{}, rtypes.Slice()...); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID)
			if err != nil {
				continue
			}

			totype := string(a.Asset.AssetType())
			if since, ok := sinces[totype]; !ok || (ok && a.LastSeen.Before(since)) {
				continue
			}

			oamu := asset.Asset.(*url.URL)
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "URL: " + oamu.Raw,
				To:       a,
				ToName:   a.Asset.Key(),
				Rel:      edge.Relation,
			})
		}
	}

	return findings
}

func (u *urlexpand) store(e *et.Event, tstr string, asset *dbt.Entity, src *et.Source, m *config.Matches) []*support.Finding {
	oamu := asset.Asset.(*url.URL)
	var findings []*support.Finding

	if tstr == string(oam.FQDN) && m.IsMatch(string(oam.FQDN)) {
		if a, err := e.Session.DB().Create(asset, "domain", &domain.FQDN{
			Name: oamu.Host,
		}); err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", u.source)
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "URL: " + oamu.Raw,
				To:       a,
				ToName:   oamu.Host,
				Rel:      "domain",
			})
		}
	} else if ip, err := netip.ParseAddr(oamu.Host); err == nil && m.IsMatch(string(oam.IPAddress)) {
		ntype := "IPv4"
		if ip.Is6() {
			ntype = "IPv6"
		}

		if a, err := e.Session.DB().Create(asset, "ip_address", &oamnet.IPAddress{
			Address: ip,
			Type:    ntype,
		}); err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", u.source)
			findings = append(findings, &support.Finding{
				From:     asset,
				FromName: "URL: " + oamu.Raw,
				To:       a,
				ToName:   ip.String(),
				Rel:      "ip_address",
			})
		}
	}

	return findings
}

func (u *urlexpand) process(e *et.Event, findings []*support.Finding, src *et.Source) {
	support.ProcessAssetsWithSource(e, findings, u.source, u.name, u.name+"-Handler")
}
