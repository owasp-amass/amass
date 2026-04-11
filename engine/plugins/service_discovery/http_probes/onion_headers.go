// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

type onionHeaders struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

// NewOnionHeaders returns a Plugin that extracts .onion URLs from the
// Onion-Location HTTP response header and stores them as OAM URL assets.
func NewOnionHeaders() et.Plugin {
	return &onionHeaders{
		name: "Onion-Location-Headers",
		source: &et.Source{
			Name:       "Onion-Location-Headers",
			Confidence: 90,
		},
	}
}

func (oh *onionHeaders) Name() string {
	return oh.name
}

func (oh *onionHeaders) Start(r et.Registry) error {
	oh.log = r.Log().WithGroup("plugin").With("name", oh.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       oh,
		Name:         oh.name + "-Handler",
		Position:     10,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.URL)},
		EventType:    oam.Service,
		Callback:     oh.check,
	}); err != nil {
		return err
	}

	oh.log.Info("Plugin started")
	return nil
}

func (oh *onionHeaders) Stop() {
	oh.log.Info("Plugin stopped")
}

func (oh *onionHeaders) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*platform.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Service), string(oam.URL), oh.name)
	if err != nil {
		return err
	}

	var urls []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, oh.source, since) {
		urls = append(urls, oh.query(e, e.Entity)...)
		support.MarkAssetMonitored(e.Session, e.Entity, oh.source)
	}

	if len(urls) > 0 {
		oh.process(e, urls)
	}
	return nil
}

func (oh *onionHeaders) query(e *et.Event, asset *dbt.Entity) []*dbt.Entity {
	serv := asset.Asset.(*platform.Service)

	var results []*oamurl.URL
	if vals, ok := serv.Attributes["Onion-Location"]; ok {
		for _, val := range vals {
			if u := extractOnionURL(val); u != nil {
				results = append(results, u)
			}
		}
	}

	return oh.store(e, results)
}

// extractOnionURL parses and validates a potential .onion URL string.
// It ensures the value is a well-formed URL whose host ends in ".onion".
// Returns nil for any input that does not satisfy these requirements.
func extractOnionURL(raw string) *oamurl.URL {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil
	}
	if !strings.HasPrefix(raw, "http://") && !strings.HasPrefix(raw, "https://") {
		raw = "https://" + raw
	}
	u := support.RawURLToOAM(raw)
	if u == nil || !strings.HasSuffix(strings.ToLower(u.Host), ".onion") {
		return nil
	}
	return u
}

func (oh *onionHeaders) store(e *et.Event, urls []*oamurl.URL) []*dbt.Entity {
	var assets []*dbt.Entity

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	for _, u := range urls {
		if a, err := e.Session.DB().CreateAsset(ctx, u); err == nil && a != nil {
			assets = append(assets, a)
			_, _ = e.Session.DB().CreateEntityProperty(ctx, a, &general.SourceProperty{
				Source:     oh.source.Name,
				Confidence: oh.source.Confidence,
			})
		}
	}

	return assets
}

// process dispatches URL events for each discovered .onion URL asset.
// Unlike bannerURLs, .onion URLs are dispatched regardless of session scope
// since they are explicit findings from HTTP headers and will not appear in
// typical domain-based scope configurations.
func (oh *onionHeaders) process(e *et.Event, assets []*dbt.Entity) {
	for _, a := range assets {
		if u, ok := a.Asset.(*oamurl.URL); ok {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    u.Raw,
				Entity:  a,
				Session: e.Session,
			})
			oh.log.Info("onion URL discovered", "url", u.Raw)
		}
	}
}
