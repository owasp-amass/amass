// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package fofa reverse-searches FOFA for the origin hosts that serve a
// fingerprint the organization already has. On an in-scope favicon_mmh3 or JARM
// Identifier it asks FOFA which hosts serve the same value and records each hit
// as an IPAddress enqueued for probing (reverse-search-collectors-spec.md).
package fofa

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

type fofa struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

// NewFOFA returns the FOFA reverse-search plugin.
func NewFOFA() et.Plugin {
	return &fofa{
		name:   "FOFA",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 2),
		source: &et.Source{Name: "FOFA", Confidence: 70},
	}
}

func (f *fofa) Name() string { return f.name }

func (f *fofa) Start(r et.Registry) error {
	f.log = r.Log().WithGroup("plugin").With("name", f.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       f,
		Name:         f.name + "-Handler",
		Position:     50,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.Identifier,
		Callback:     f.check,
	}); err != nil {
		return err
	}

	f.log.Info("Plugin started")
	return nil
}

func (f *fofa) Stop() { f.log.Info("Plugin stopped") }

func (f *fofa) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}

	qb64, ok := reversesearch.FofaQueryBase64(ident.Type, ident.ID)
	if !ok {
		return nil
	}
	if !support.FingerprintCarrierInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(f.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}
	// FOFA authenticates with an account email (username) and an API key.
	var email, key string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Username != "" && cr.Apikey != "" {
			email, key = cr.Username, cr.Apikey
			break
		}
	}
	if email == "" || key == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.IPAddress), f.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, f.source, since) {
		return nil
	}

	for _, h := range f.query(e, qb64, email, key) {
		support.StoreOriginIP(e, f.source, h.IP)
	}
	support.MarkAssetMonitored(e.Session, e.Entity, f.source)
	return nil
}

func (f *fofa) query(e *et.Event, qb64, email, key string) []reversesearch.Hit {
	_ = support.WaitLimit(e.Session.Ctx(), f.rlimit)
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	u := "https://fofa.info/api/v1/search/all?fields=ip,port&size=100" +
		"&email=" + url.QueryEscape(email) + "&key=" + url.QueryEscape(key) + "&qbase64=" + url.QueryEscape(qb64)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{URL: u})
	if err != nil {
		return nil
	}

	hits, err := reversesearch.ParseFofa([]byte(resp.Body))
	if err != nil {
		return nil
	}

	return hits
}
