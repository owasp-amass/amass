// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package censys reverse-searches Censys for the origin hosts that serve a
// fingerprint the organization already has. Censys indexes the JARM and the MD5
// favicon hash (not the mmh3 favicon Amass stores), so it acts on JARM (and a
// future favicon_md5) Identifiers carried by an in-scope host, recording each
// hit as an IPAddress enqueued for probing (reverse-search-collectors-spec.md).
package censys

import (
	"context"
	"encoding/base64"
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

type censys struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

// NewCensys returns the Censys reverse-search plugin.
func NewCensys() et.Plugin {
	return &censys{
		name:   "Censys",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 2),
		source: &et.Source{Name: "Censys", Confidence: 70},
	}
}

func (c *censys) Name() string { return c.name }

func (c *censys) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-Handler",
		Position:     50,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.Identifier,
		Callback:     c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *censys) Stop() { c.log.Info("Plugin stopped") }

func (c *censys) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}

	query, ok := reversesearch.CensysQuery(ident.Type, ident.ID)
	if !ok {
		return nil
	}
	if !support.FingerprintCarrierInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(c.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}
	// Censys authenticates with an API ID (username) and secret.
	var id, secret string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Username != "" && cr.Secret != "" {
			id, secret = cr.Username, cr.Secret
			break
		}
	}
	if id == "" || secret == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.IPAddress), c.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		return nil
	}

	for _, h := range c.query(e, query, id, secret) {
		support.StoreOriginIP(e, c.source, h.IP)
	}
	support.MarkAssetMonitored(e.Session, e.Entity, c.source)
	return nil
}

func (c *censys) query(e *et.Event, query, id, secret string) []reversesearch.Hit {
	_ = support.WaitLimit(e.Session.Ctx(), c.rlimit)
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	u := "https://search.censys.io/api/v2/hosts/search?per_page=50&q=" + url.QueryEscape(query)
	auth := base64.StdEncoding.EncodeToString([]byte(id + ":" + secret))
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    u,
		Header: amasshttp.Header{"Authorization": []string{"Basic " + auth}},
	})
	if err != nil {
		return nil
	}

	hits, err := reversesearch.ParseCensys([]byte(resp.Body))
	if err != nil {
		return nil
	}

	return hits
}
