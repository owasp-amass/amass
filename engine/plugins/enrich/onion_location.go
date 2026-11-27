// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enrich

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
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

// onionLocationHeader is the response header a site uses to advertise its
// Tor onion service address (Tor Browser offers to switch to it).
const onionLocationHeader = "Onion-Location"

// onionLocation records the Tor onion address a web service advertises for
// itself in its Onion-Location response header, as a URL linked from the
// Service by onion_location. It reads the headers the HTTP probe already
// stored on the Service, so it sends no request of its own. The onion URL is
// stored but not dispatched: the engine cannot resolve or reach .onion hosts.
//
// The idea and the header parsing come from rxerium's ".onion Service
// Discovery" proposal (owasp-amass/amass#1114).
type onionLocation struct {
	name   string
	log    *slog.Logger
	source *et.Source
}

// NewOnionLocation returns the plugin that records advertised onion services.
func NewOnionLocation() et.Plugin {
	return &onionLocation{
		name: "Onion-Location",
		source: &et.Source{
			Name:       "Onion-Location",
			Confidence: 90,
		},
	}
}

func (ol *onionLocation) Name() string {
	return ol.name
}

func (ol *onionLocation) Start(r et.Registry) error {
	ol.log = r.Log().WithGroup("plugin").With("name", ol.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       ol,
		Name:         ol.name + "-Handler",
		Position:     11,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.URL)},
		EventType:    oam.Service,
		Callback:     ol.check,
	}); err != nil {
		return err
	}

	ol.log.Info("Plugin started")
	return nil
}

func (ol *onionLocation) Stop() {
	ol.log.Info("Plugin stopped")
}

func (ol *onionLocation) check(e *et.Event) error {
	serv, ok := e.Entity.Asset.(*platform.Service)
	if !ok {
		return errors.New("failed to extract the Service asset")
	}

	urls := onionURLs(serv.Attributes)
	if len(urls) == 0 {
		return nil
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	for _, u := range urls {
		ent, err := e.Session.DB().CreateAsset(ctx, u)
		if err != nil || ent == nil {
			continue
		}
		support.AddSource(ctx, e.Session, ent, ol.source)
		ol.link(ctx, e, ent)
		e.Session.Log().Info("onion service advertised", "service", serv.ID, "url", u.Raw,
			slog.Group("plugin", "name", ol.name, "handler", ol.name+"-Handler"))
	}
	return nil
}

// link records the Service --onion_location--> URL relationship.
func (ol *onionLocation) link(ctx context.Context, e *et.Event, u *dbt.Entity) {
	_, _ = support.Relate(ctx, e.Session, e.Entity, &general.SimpleRelation{Name: "onion_location"}, u, ol.source)
}

// onionURLs returns the onion service URLs a response's Onion-Location
// header names, once each.
func onionURLs(headers map[string][]string) []*oamurl.URL {
	var out []*oamurl.URL
	seen := map[string]bool{}
	for k, vals := range headers {
		if http.CanonicalHeaderKey(k) != onionLocationHeader {
			continue
		}
		for _, v := range vals {
			if u := extractOnionURL(v); u != nil && !seen[u.Raw] {
				seen[u.Raw] = true
				out = append(out, u)
			}
		}
	}
	return out
}

// extractOnionURL parses an Onion-Location value into a URL whose host is a
// .onion name, or nil. A value without a scheme is read as https. (From
// owasp-amass/amass#1114.)
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
