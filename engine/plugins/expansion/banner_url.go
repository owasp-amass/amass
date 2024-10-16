// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package expansion

import (
	"errors"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/service"
	"github.com/owasp-amass/open-asset-model/source"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type bannerURLs struct {
	name   string
	log    *slog.Logger
	source *source.Source
}

func NewBannerURLs() et.Plugin {
	return &bannerURLs{
		name: "Service-Banner-URLs",
		source: &source.Source{
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
	_, ok := e.Asset.Asset.(*service.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	src := support.GetSource(e.Session, bu.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Service), string(oam.URL), bu.name)
	if err != nil {
		return err
	}

	var urls []*dbt.Asset
	//TODO: urls = append(urls, bu.lookup(e, serv.Identifier, src, since)...)
	if !support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		urls = append(urls, bu.query(e, e.Asset, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(urls) > 0 {
		bu.process(e, urls, src)
	}
	return nil
}

func (bu *bannerURLs) query(e *et.Event, asset, src *dbt.Asset) []*dbt.Asset {
	serv := asset.Asset.(*service.Service)

	if serv.BannerLen == 0 {
		return nil
	}

	var results []*dbt.Asset
	if urls := support.ExtractURLsFromString(serv.Banner); len(urls) > 0 {
		results = append(results, bu.store(e, urls, src)...)
	}
	return results
}

func (bu *bannerURLs) store(e *et.Event, urls []*oamurl.URL, src *dbt.Asset) []*dbt.Asset {
	var assets []*dbt.Asset

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		for _, u := range urls {
			if a, err := e.Session.DB().Create(nil, "", u); err == nil && a != nil {
				assets = append(assets, a)
				_, _ = e.Session.DB().Link(a, "source", src)
			}
		}
	})
	<-done
	close(done)
	return assets
}

func (bu *bannerURLs) process(e *et.Event, assets []*dbt.Asset, src *dbt.Asset) {
	for _, a := range assets {
		if u, ok := a.Asset.(*oamurl.URL); ok && e.Session.Scope().IsURLInScope(e.Session.Cache(), u) {
			bu.processOneURL(e, u.Raw, a, src)
		}
	}
}

func (bu *bannerURLs) processOneURL(e *et.Event, name string, asset, src *dbt.Asset) {
	now := time.Now()

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    name,
		Asset:   asset,
		Session: e.Session,
	})

	if to, hit := e.Session.Cache().GetAsset(asset.Asset); hit && to != nil {
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: asset,
			ToAsset:   src,
		})
	}
}
