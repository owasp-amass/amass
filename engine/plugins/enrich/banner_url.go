// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
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
		Plugin:       bu,
		Name:         bu.name + "-Handler",
		Position:     10,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.URL), string(oam.Identifier)},
		EventType:    oam.Service,
		Callback:     bu.check,
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

	bu.emails(e, serv.Output)

	var results []*oamurl.URL
	static := semantics.ArchiveURLs()
	// TODO: in the future, further investigation of out of scope URLs may be needed
	if urls := support.ExtractURLsFromString(serv.Output); len(urls) > 0 {
		for _, u := range urls {
			// images, stylesheets, fonts and media say nothing about the
			// attack surface (the same list the archive collectors skip)
			if u.Host == "" || static.IsStaticPath(u.Path) {
				continue
			} else if addr, err := netip.ParseAddr(u.Host); err == nil {
				if _, conf := e.Session.Scope().IsAssetInScope(&oamnet.IPAddress{Address: addr}, 0); conf > 0 {
					results = append(results, u)
				}
			} else if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: u.Host}, 0); conf > 0 {
				results = append(results, u)
			}
		}
	}

	return bu.store(e, results)
}

// emails stores the in-scope email addresses a response names (mailto: links
// and bare addresses) as email Identifiers, so the breach and account lenses
// see them; they are never made into URLs.
func (bu *bannerURLs) emails(e *et.Event, body string) {
	var inscope []string
	for _, addr := range support.ExtractEmailsFromString(body) {
		_, domain, ok := strings.Cut(addr, "@")
		if !ok {
			continue
		}
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: domain}, 0); conf > 0 {
			inscope = append(inscope, addr)
		}
	}
	if len(inscope) == 0 {
		return
	}

	ents := support.StoreEmailsWithSource(e.Session, inscope, bu.source, bu.name, bu.name+"-Handler")
	support.ProcessEmailsWithSource(e, ents, bu.source)
}

func (bu *bannerURLs) store(e *et.Event, urls []*oamurl.URL) []*dbt.Entity {
	var assets []*dbt.Entity

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	for _, u := range urls {
		if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
			assets = append(assets, a)
			support.AddSource(ctx, e.Session, a, bu.source)
		}
	}

	return assets
}

func (bu *bannerURLs) process(e *et.Event, assets []*dbt.Entity) {
	for _, a := range assets {
		if u, ok := a.Asset.(*oamurl.URL); ok {
			if _, conf := e.Session.Scope().IsAssetInScope(u, 0); conf > 0 {
				bu.processOneURL(e, u.Raw, a)
			}
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
