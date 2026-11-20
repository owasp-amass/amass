// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package zoomeye reverse-searches ZoomEye for the origin hosts that serve a
// fingerprint the organization already has. On an in-scope favicon_mmh3 or JARM
// Identifier it asks ZoomEye which hosts serve the same value and records each
// hit as an IPAddress enqueued for probing (reverse-search-collectors-spec.md).
package zoomeye

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

type zoomeye struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

// NewZoomEye returns the ZoomEye reverse-search plugin.
func NewZoomEye() et.Plugin {
	return &zoomeye{
		name:   "ZoomEye",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 2),
		source: &et.Source{Name: "ZoomEye", Confidence: 70},
	}
}

func (z *zoomeye) Name() string { return z.name }

func (z *zoomeye) Start(r et.Registry) error {
	z.log = r.Log().WithGroup("plugin").With("name", z.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       z,
		Name:         z.name + "-Handler",
		Position:     50,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.Identifier,
		Callback:     z.check,
	}); err != nil {
		return err
	}

	z.log.Info("Plugin started")
	return nil
}

func (z *zoomeye) Stop() { z.log.Info("Plugin stopped") }

func (z *zoomeye) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}

	query, ok := reversesearch.ZoomEyeQuery(ident.Type, ident.ID)
	if !ok {
		return nil
	}
	if !support.FingerprintCarrierInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(z.name)
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

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.IPAddress), z.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, z.source, since) {
		return nil
	}

	for _, h := range z.query(e, query, key) {
		support.StoreOriginIP(e, z.source, h.IP)
	}
	support.MarkAssetMonitored(e.Session, e.Entity, z.source)
	return nil
}

func (z *zoomeye) query(e *et.Event, query, key string) []reversesearch.Hit {
	_ = support.WaitLimit(e.Session.Ctx(), z.rlimit)
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	u := "https://api.zoomeye.org/host/search?query=" + url.QueryEscape(query)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    u,
		Header: amasshttp.Header{"API-KEY": []string{key}},
	})
	if err != nil {
		return nil
	}

	hits, err := reversesearch.ParseZoomEye([]byte(resp.Body))
	if err != nil {
		return nil
	}

	return hits
}
