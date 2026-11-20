// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package shodan reverse-searches Shodan for the origin hosts that serve a
// fingerprint the organization already has. On a fingerprint Identifier
// (favicon_mmh3 or JARM) carried by an in-scope host, it asks Shodan which IPs
// serve the same value — candidate origins behind a CDN/WAF — and records each
// as an IPAddress with Shodan provenance, then enqueues it for Amass's own
// service discovery to probe (ai-design-principles.md, principle 10;
// reverse-search-collectors-spec.md).
package shodan

import (
	"context"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"golang.org/x/time/rate"
)

type shodan struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

// NewShodan returns the Shodan reverse-search plugin.
func NewShodan() et.Plugin {
	return &shodan{
		name:   "Shodan",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 2),
		source: &et.Source{Name: "Shodan", Confidence: 70},
	}
}

func (s *shodan) Name() string { return s.name }

func (s *shodan) Start(r et.Registry) error {
	s.log = r.Log().WithGroup("plugin").With("name", s.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       s,
		Name:         s.name + "-Handler",
		Position:     50,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.Identifier,
		Callback:     s.check,
	}); err != nil {
		return err
	}

	s.log.Info("Plugin started")
	return nil
}

func (s *shodan) Stop() { s.log.Info("Plugin stopped") }

func (s *shodan) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}

	query, ok := reversesearch.ShodanQuery(ident.Type, ident.ID)
	if !ok {
		return nil
	}
	if !support.FingerprintCarrierInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(s.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}
	var key string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			key = cr.Apikey
			break
		}
	}
	if key == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.IPAddress), s.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, s.source, since) {
		return nil
	}

	for _, h := range s.query(e, query, key) {
		support.StoreOriginIP(e, s.source, h.IP)
	}
	support.MarkAssetMonitored(e.Session, e.Entity, s.source)
	return nil
}

func (s *shodan) query(e *et.Event, query, key string) []reversesearch.Hit {
	_ = support.WaitLimit(e.Session.Ctx(), s.rlimit)
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	u := "https://api.shodan.io/shodan/host/search?key=" + url.QueryEscape(key) + "&query=" + url.QueryEscape(query)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil {
		return nil
	}

	hits, err := reversesearch.ParseShodan([]byte(resp.Body))
	if err != nil {
		return nil
	}

	return hits
}
