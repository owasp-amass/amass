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
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type fullhunt struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewFullHunt() et.Plugin {
	limit := rate.Every(10 * time.Second)

	return &fullhunt{
		name:   "FullHunt",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "FullHunt",
			Confidence: 80,
		},
	}
}

func (fh *fullhunt) Name() string {
	return fh.name
}

func (fh *fullhunt) Start(r et.Registry) error {
	fh.log = r.Log().WithGroup("plugin").With("name", fh.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       fh,
		Name:         fh.name + "-Handler",
		Position:     35,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     fh.check,
	}); err != nil {
		return err
	}

	fh.log.Info("Plugin started")
	return nil
}

func (fh *fullhunt) Stop() {
	if fh.log != nil {
		fh.log.Info("Plugin stopped")
	}
}

func (fh *fullhunt) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(fh.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), fh.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, fh.source, since) {
		names = append(names, fh.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, fh.source)
	}

	if len(names) > 0 {
		fh.process(e, names)
	}
	return nil
}

func (fh *fullhunt) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = fh.rlimit.Wait(e.Session.Ctx())
		e.Session.NetSem().Acquire()

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
		resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
			URL: "https://fullhunt.io/api/v1/domain/" + name + "/subdomains",
			Header: amasshttp.Header{
				"Accept":    []string{"application/json"},
				"X-API-KEY": []string{key},
			},
		})
		cancel()
		e.Session.NetSem().Release()
		if err != nil || resp.Body == "" {
			continue
		}

		var result struct {
			Hosts      []string `json:"hosts"`
			Subdomains []string `json:"subdomains"`
			Records    []struct {
				Host string `json:"host"`
			} `json:"records"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		var candidates []string
		candidates = append(candidates, result.Hosts...)
		candidates = append(candidates, result.Subdomains...)
		for _, rec := range result.Records {
			if rec.Host != "" {
				candidates = append(candidates, rec.Host)
			}
		}

		for _, item := range candidates {
			item = amassdns.RemoveAsteriskLabel(item)
			if !strings.HasSuffix(item, "."+name) && item != name {
				item = item + "." + name
			}
			item = strings.ToLower(strings.Trim(item, "."))
			if item == "" {
				continue
			}

			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: item}, 0); conf > 0 {
				names = append(names, item)
			}
		}
		break
	}

	return fh.store(e, names)
}

func (fh *fullhunt) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, fh.source, fh.name, fh.name+"-Handler")
}

func (fh *fullhunt) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, fh.source)
}
