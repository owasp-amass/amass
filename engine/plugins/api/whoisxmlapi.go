// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type whoisXMLAPI struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewWhoisXMLAPI() et.Plugin {
	limit := rate.Every(500 * time.Millisecond)

	return &whoisXMLAPI{
		name:   "WhoisXMLAPI",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "WhoisXMLAPI",
			Confidence: 80,
		},
	}
}

func (w *whoisXMLAPI) Name() string {
	return w.name
}

func (w *whoisXMLAPI) Start(r et.Registry) error {
	w.log = r.Log().WithGroup("plugin").With("name", w.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       w,
		Name:         w.name + "-Handler",
		Position:     26,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     w.check,
	}); err != nil {
		return err
	}

	w.log.Info("Plugin started")
	return nil
}

func (w *whoisXMLAPI) Stop() {
	w.log.Info("Plugin stopped")
}

func (w *whoisXMLAPI) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(w.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), w.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, w.source, since) {
		names = append(names, w.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, w.source)
	}

	if len(names) > 0 {
		w.process(e, names)
	}
	return nil
}

func (w *whoisXMLAPI) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = w.rlimit.Wait(e.Session.Ctx())
		e.Session.NetSem().Acquire()

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
		defer cancel()

		resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
			URL: "https://subdomains.whoisxmlapi.com/api/v1?apiKey=" + key + "&domainName=" + name,
		})
		e.Session.NetSem().Release()
		if err != nil {
			continue
		}

		var result struct {
			Result struct {
				Count   int `json:"count"`
				Records []struct {
					Domain string `json:"domain"`
				} `json:"records"`
			} `json:"result"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		for _, r := range result.Result.Records {
			n := strings.ToLower(strings.TrimSpace(r.Domain))
			if n != "" {
				if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
					names = append(names, n)
				}
			}
		}
		break
	}

	return w.store(e, names)
}

func (w *whoisXMLAPI) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, w.source, w.name, w.name+"-Handler")
}

func (w *whoisXMLAPI) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, w.source)
}
