// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"net/netip"
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/reversesearch"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// OriginSource describes one reverse-search source for NewOriginSearch: how it
// phrases a fingerprint query, the request it sends with one set of
// credentials, and how it reads the answer.
type OriginSource struct {
	// Name is the plugin, data source and provenance name.
	Name string
	// Query builds the source's query for a fingerprint, or ok=false when the
	// source cannot key on the fingerprint's id_type.
	Query func(idType, value string) (string, bool)
	// Request builds the search request for a query with one set of
	// credentials, or nil when the credentials lack what the source needs.
	Request func(query string, cred *config.Credentials) *amasshttp.Request
	// Parse reads the source's answer into origin hits.
	Parse func(data []byte) ([]reversesearch.Hit, error)
}

type originSearch struct {
	src    OriginSource
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

// NewOriginSearch returns a reverse-search plugin for src. On a fingerprint
// Identifier carried by an in-scope host it asks the source which other hosts
// serve the same value, and records each as an IPAddress with the source's
// provenance, enqueued for Amass's own service discovery to probe
// (StoreOriginIP). It runs only when the source's credentials are configured,
// at most once per fingerprint within the Identifier to IPAddress TTL.
func NewOriginSearch(src OriginSource) et.Plugin {
	return &originSearch{
		src:    src,
		rlimit: rate.NewLimiter(rate.Every(time.Second), 2),
		source: &et.Source{Name: src.Name, Confidence: 70},
	}
}

func (o *originSearch) Name() string { return o.src.Name }

func (o *originSearch) Start(r et.Registry) error {
	o.log = r.Log().WithGroup("plugin").With("name", o.src.Name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       o,
		Name:         o.src.Name + "-Handler",
		Position:     50,
		MaxInstances: MidHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.Identifier,
		Callback:     o.check,
	}); err != nil {
		return err
	}

	o.log.Info("Plugin started")
	return nil
}

func (o *originSearch) Stop() { o.log.Info("Plugin stopped") }

func (o *originSearch) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}

	query, ok := o.src.Query(ident.Type, ident.ID)
	if !ok {
		return nil
	}
	req := o.request(e.Session.Config(), query)
	if req == nil {
		return nil
	}

	since, err := TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.IPAddress), o.src.Name)
	if err != nil {
		return err
	}
	if AssetMonitoredWithinTTL(e.Session, e.Entity, o.source, since) {
		return nil
	}

	for _, h := range o.search(e, req) {
		StoreOriginIP(e, o.source, h.IP)
	}
	MarkAssetMonitored(e.Session, e.Entity, o.source)
	return nil
}

// request returns the search request built with the first configured
// credentials, in account-name order, that the source can use.
func (o *originSearch) request(cfg *config.Config, query string) *amasshttp.Request {
	ds := cfg.GetDataSourceConfig(o.src.Name)
	if ds == nil {
		return nil
	}
	names := make([]string, 0, len(ds.Creds))
	for name := range ds.Creds {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if cr := ds.Creds[name]; cr != nil {
			if req := o.src.Request(query, cr); req != nil {
				return req
			}
		}
	}
	return nil
}

func (o *originSearch) search(e *et.Event, req *amasshttp.Request) []reversesearch.Hit {
	_ = WaitLimit(e.Session.Ctx(), o.rlimit)
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil
	}
	hits, err := o.src.Parse([]byte(resp.Body))
	if err != nil {
		return nil
	}
	return hits
}

// StoreOriginIP records a reverse-search hit as an IPAddress with src
// provenance and enqueues it for Amass's own service discovery to probe. No
// Service or fingerprint edge is synthesized: a third-party report becomes an
// Amass observation only when a probe confirms it (ai-design-principles.md,
// principle 10). It reports whether the address was stored.
func StoreOriginIP(e *et.Event, src *et.Source, ip string) bool {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}

	ipa := &oamnet.IPAddress{Address: addr, Type: "IPv4"}
	if addr.Is6() {
		ipa.Type = "IPv6"
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	ent, err := e.Session.DB().CreateAsset(ctx, ipa)
	if err != nil || ent == nil {
		return false
	}

	AddSource(ctx, e.Session, ent, src)
	_ = e.Session.Backlog().Enqueue(ent)

	return true
}
