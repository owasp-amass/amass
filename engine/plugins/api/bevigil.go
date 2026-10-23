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

type bevigil struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewBeVigil() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &bevigil{
		name:   "BeVigil",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "BeVigil",
			Confidence: 80,
		},
	}
}

func (bv *bevigil) Name() string {
	return bv.name
}

func (bv *bevigil) Start(r et.Registry) error {
	bv.log = r.Log().WithGroup("plugin").With("name", bv.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       bv,
		Name:         bv.name + "-Handler",
		Position:     34,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     bv.check,
	}); err != nil {
		return err
	}

	bv.log.Info("Plugin started")
	return nil
}

func (bv *bevigil) Stop() {
	if bv.log != nil {
		bv.log.Info("Plugin stopped")
	}
}

func (bv *bevigil) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(bv.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), bv.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, bv.source, since) {
		names = append(names, bv.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, bv.source)
	}

	if len(names) > 0 {
		bv.process(e, names)
	}
	return nil
}

func (bv *bevigil) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = bv.rlimit.Wait(e.Session.Ctx())
		e.Session.NetSem().Acquire()

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
		resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
			URL: "https://osint.bevigil.com/api/" + name + "/subdomains/",
			Header: amasshttp.Header{
				"Accept":         []string{"application/json"},
				"X-Access-Token": []string{key},
			},
		})
		cancel()
		e.Session.NetSem().Release()
		if err != nil || resp.Body == "" {
			continue
		}

		var result struct {
			Domain     string   `json:"domain"`
			Subdomains []string `json:"subdomains"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		for _, sub := range result.Subdomains {
			sub = amassdns.RemoveAsteriskLabel(sub)
			if !strings.HasSuffix(sub, "."+name) && sub != name {
				sub = sub + "." + name
			}
			sub = strings.ToLower(strings.Trim(sub, "."))
			if sub == "" {
				continue
			}

			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: sub}, 0); conf > 0 {
				names = append(names, sub)
			}
		}
		break
	}

	return bv.store(e, names)
}

func (bv *bevigil) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, bv.source, bv.name, bv.name+"-Handler")
}

func (bv *bevigil) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, bv.source)
}
