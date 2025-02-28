// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"errors"
	"log/slog"
	"net/netip"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type bannerURLs struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

func NewBannerURLs() et.Plugin {
	return &bannerURLs{
		name: "Service-Banner-URLs",
		source: &et.Source{
			Name:       "Service-Banner-URLs",
			Confidence: 80,
		},
	}
}

func (bu *bannerURLs) Name() string {
	return bu.name
}

func (bu *bannerURLs) Start(r et.Registry) error {
	bu.log = r.Log().WithGroup("plugin").With("name", bu.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     bu,
		Name:       bu.name + "-Handler",
		Transforms: []string{string(oam.URL)},
		EventType:  oam.Service,
		Callback:   bu.check,
	}); err != nil {
		return err
	}

	bu.log.Info("Plugin started")
	return nil
}

func (bu *bannerURLs) Stop() {
	bu.log.Info("Plugin stopped")
}

func (bu *bannerURLs) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*platform.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Service), string(oam.URL), bu.name)
	if err != nil {
		return err
	}

	var urls []*dbt.Entity
	//TODO: urls = append(urls, bu.lookup(e, serv.Identifier, bu.source, since)...)
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, bu.source, since) {
		urls = append(urls, bu.query(e, e.Entity)...)
		support.MarkAssetMonitored(e.Session, e.Entity, bu.source)
	}

	if len(urls) > 0 {
		bu.process(e, urls)
	}
	return nil
}

func (bu *bannerURLs) query(e *et.Event, asset *dbt.Entity) []*dbt.Entity {
	serv := asset.Asset.(*platform.Service)

	if serv.OutputLen == 0 {
		return nil
	}

	var results []*oamurl.URL
	// TODO: in the future, further investigation of out of scope URLs may be needed
	if urls := support.ExtractURLsFromString(serv.Output); len(urls) > 0 {
		for _, u := range urls {
			if addr, err := netip.ParseAddr(u.Host); err == nil {
				if _, conf := e.Session.Scope().IsAssetInScope(&oamnet.IPAddress{Address: addr}, 0); conf > 0 {
					results = append(results, u)
				}
			} else {
				if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: u.Host}, 0); conf > 0 {
					results = append(results, u)
				}
			}
		}
	}

	return bu.store(e, results)
}

func (bu *bannerURLs) store(e *et.Event, urls []*oamurl.URL) []*dbt.Entity {
	var assets []*dbt.Entity

	for _, u := range urls {
		if a, err := e.Session.Cache().CreateAsset(u); err == nil && a != nil {
			assets = append(assets, a)
			_, _ = e.Session.Cache().CreateEntityProperty(a, &general.SourceProperty{
				Source:     bu.source.Name,
				Confidence: bu.source.Confidence,
			})
		}
	}

	return assets
}

func (bu *bannerURLs) process(e *et.Event, assets []*dbt.Entity) {
	for _, a := range assets {
		if u, ok := a.Asset.(*oamurl.URL); ok && e.Session.Scope().IsURLInScope(e.Session.Cache(), u) {
			bu.processOneURL(e, u.Raw, a)
		}
	}
}

func (bu *bannerURLs) processOneURL(e *et.Event, name string, asset *dbt.Entity) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    name,
		Entity:  asset,
		Session: e.Session,
	})
}
