// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package expansion

import (
	"errors"
	"log/slog"
	"net/netip"
	"strconv"
	"time"

	"github.com/caffix/stringset"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/config/config"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/source"
	"github.com/owasp-amass/open-asset-model/url"
)

type urlexpand struct {
	name       string
	log        *slog.Logger
	transforms []string
	source     *source.Source
}

func NewURLs() et.Plugin {
	return &urlexpand{
		name: "URL-Expansion",
		transforms: []string{
			string(oam.FQDN),
			string(oam.NetworkEndpoint),
			string(oam.IPAddress),
			string(oam.SocketAddress),
			string(oam.Service),
		},
		source: &source.Source{
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
	oamu, ok := e.Asset.Asset.(*url.URL)
	if !ok {
		return errors.New("failed to extract the URL asset")
	}

	src := support.GetSource(e.Session, u.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
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
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		if inscope {
			findings = append(findings, u.lookup(e, e.Asset, matches)...)
		}
	} else {
		findings = append(findings, u.store(e, tstr, e.Asset, src, matches)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if inscope && len(findings) > 0 {
		u.process(e, findings, src)
	}
	return nil
}

func (u *urlexpand) lookup(e *et.Event, asset *dbt.Asset, m *config.Matches) []*support.Finding {
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
		case string(oam.NetworkEndpoint):
			rtypes.Insert("port")
		case string(oam.IPAddress):
			rtypes.Insert("ip_address")
		case string(oam.SocketAddress):
			rtypes.Insert("port")
		case string(oam.Service):
			rtypes.Insert("service")
		}
	}

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if rels, err := e.Session.DB().OutgoingRelations(asset, time.Time{}, rtypes.Slice()...); err == nil && len(rels) > 0 {
			for _, rel := range rels {
				a, err := e.Session.DB().FindById(rel.ToAsset.ID, time.Time{})
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
					Rel:      rel.Type,
				})
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (u *urlexpand) store(e *et.Event, tstr string, asset, src *dbt.Asset, m *config.Matches) []*support.Finding {
	oamu := asset.Asset.(*url.URL)
	var findings []*support.Finding

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		if tstr == string(oam.FQDN) {
			if m.IsMatch(string(oam.FQDN)) {
				if a, err := e.Session.DB().Create(asset, "domain", &domain.FQDN{
					Name: oamu.Host,
				}); err == nil && a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "URL: " + oamu.Raw,
						To:       a,
						ToName:   oamu.Host,
						Rel:      "domain",
					})
				}
			}
			if m.IsMatch(string(oam.NetworkEndpoint)) {
				addr := oamu.Host + ":" + strconv.Itoa(oamu.Port)

				if a, err := e.Session.DB().Create(asset, "port", &domain.NetworkEndpoint{
					Address:  addr,
					Name:     oamu.Host,
					Port:     oamu.Port,
					Protocol: oamu.Scheme,
				}); err == nil && a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "URL: " + oamu.Raw,
						To:       a,
						ToName:   addr,
						Rel:      "port",
					})
				}
			}
		} else if ip, err := netip.ParseAddr(oamu.Host); err == nil {
			if m.IsMatch(string(oam.IPAddress)) {
				ntype := "IPv4"
				if ip.Is6() {
					ntype = "IPv6"
				}

				if a, err := e.Session.DB().Create(asset, "ip_address", &oamnet.IPAddress{
					Address: ip,
					Type:    ntype,
				}); err == nil && a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "URL: " + oamu.Raw,
						To:       a,
						ToName:   ip.String(),
						Rel:      "ip_address",
					})
				}
			}
			if m.IsMatch(string(oam.SocketAddress)) {
				addrport := ip.String() + ":" + strconv.Itoa(oamu.Port)

				if a, err := e.Session.DB().Create(asset, "port", &oamnet.SocketAddress{
					Address:   netip.MustParseAddrPort(addrport),
					IPAddress: ip,
					Port:      oamu.Port,
					Protocol:  oamu.Scheme,
				}); err == nil && a != nil {
					_, _ = e.Session.DB().Link(a, "source", src)
					findings = append(findings, &support.Finding{
						From:     asset,
						FromName: "URL: " + oamu.Raw,
						To:       a,
						ToName:   addrport,
						Rel:      "port",
					})
				}
			}
		}
	})
	<-done
	close(done)
	return findings
}

func (u *urlexpand) process(e *et.Event, findings []*support.Finding, src *dbt.Asset) {
	support.ProcessAssetsWithSource(e, findings, src, u.name, u.name+"-Handler")
}
