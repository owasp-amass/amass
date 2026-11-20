// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package shodan reverse-searches Shodan for the origin hosts that serve a
// fingerprint the organization already has. On a fingerprint Identifier
// (favicon_mmh3 or JARM) carried by an in-scope host, it asks Shodan which IPs
// serve the same value — candidate origins behind a CDN/WAF — and records each
// as an IPAddress with Shodan provenance, then enqueues it for Amass's own
// service discovery to probe. The real Service and fingerprint edge appear only
// if a probe confirms it, so a third-party report never enters the graph as an
// observation Amass did not make (ai-design-principles.md, principle 10;
// reverse-search-collectors-spec.md).
package shodan

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"net/url"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdb "github.com/owasp-amass/amass/v5/internal/db"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
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

	// Only fingerprints Shodan can key on (mmh3 favicon, JARM). The builder
	// returns ok=false for every other id_type, and a default/signal-free value
	// is not worth an API credit.
	query, ok := reversesearch.ShodanQuery(ident.Type, ident.ID)
	if !ok {
		return nil
	}

	// The fingerprint must be carried by one of the organization's own in-scope
	// hosts, not just any Identifier in the shared database.
	if !s.inScope(e) {
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

	s.store(e, s.query(e, query, key))
	support.MarkAssetMonitored(e.Session, e.Entity, s.source)
	return nil
}

// inScope reports whether the fingerprint Identifier is carried by a service on
// a host in the session scope: Identifier <--fingerprint-- Service <--port--
// FQDN/IPAddress, any of which in scope.
func (s *shodan) inScope(e *et.Event) bool {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 15*time.Second)
	defer cancel()

	fpEdges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, time.Time{}, "fingerprint")
	if err != nil || len(fpEdges) == 0 {
		return false
	}
	svcs := amassdb.EdgeEnds(ctx, e.Session.DB(), fpEdges, true)
	for _, fe := range fpEdges {
		svc, ok := svcs[fe.FromEntity.ID]
		if !ok {
			continue
		}
		portEdges, err := e.Session.DB().IncomingEdges(ctx, svc, time.Time{}, "port")
		if err != nil {
			continue
		}
		hosts := amassdb.EdgeEnds(ctx, e.Session.DB(), portEdges, true)
		for _, pe := range portEdges {
			if host, ok := hosts[pe.FromEntity.ID]; ok {
				if _, conf := e.Session.Scope().IsAssetInScope(host.Asset, 0); conf > 0 {
					return true
				}
			}
		}
	}

	return false
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

// store records each origin candidate as an IPAddress with Shodan provenance and
// enqueues it for Amass's own service discovery. No Service or fingerprint edge
// is synthesized: that comes only from a real probe.
func (s *shodan) store(e *et.Event, hits []reversesearch.Hit) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	for _, h := range hits {
		addr, err := netip.ParseAddr(h.IP)
		if err != nil {
			continue
		}
		ipa := &oamnet.IPAddress{Address: addr, Type: "IPv4"}
		if addr.Is6() {
			ipa.Type = "IPv6"
		}

		ent, err := e.Session.DB().CreateAsset(ctx, ipa)
		if err != nil || ent == nil {
			continue
		}
		_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{
			Source:     s.source.Name,
			Confidence: s.source.Confidence,
		})
		_ = e.Session.Backlog().Enqueue(ent)
	}
}
