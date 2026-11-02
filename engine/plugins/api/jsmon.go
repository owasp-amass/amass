// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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

type jsmon struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewJsmon() et.Plugin {
	limit := rate.Every(5 * time.Second)

	return &jsmon{
		name:   "Jsmon",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Jsmon",
			Confidence: 80,
		},
	}
}

func (j *jsmon) Name() string {
	return j.name
}

func (j *jsmon) Start(r et.Registry) error {
	j.log = r.Log().WithGroup("plugin").With("name", j.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       j,
		Name:         j.name + "-Handler",
		Position:     21,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     j.check,
	}); err != nil {
		return err
	}

	j.log.Info("Plugin started")
	return nil
}

func (j *jsmon) Stop() {
	j.log.Info("Plugin stopped")
}

func (j *jsmon) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(j.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), j.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, j.source, since) {
		names = append(names, j.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, j.source)
	}

	if len(names) > 0 {
		j.process(e, names)
	}
	return nil
}

func (j *jsmon) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = j.rlimit.Wait(e.Session.Ctx())
		e.Session.NetSem().Acquire()

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)

		resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
			URL:    "https://subdomains.jsmon.sh/api/domain/" + name,
			Header: amasshttp.Header{"Api-Key": []string{key}},
		})
		cancel()
		e.Session.NetSem().Release()
		if err != nil {
			continue
		}

		var result struct {
			Domain     string   `json:"domain"`
			Total      int      `json:"total"`
			Page       int      `json:"page"`
			TotalPages int      `json:"total_pages"`
			Subdomains []string `json:"subdomains"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		for _, sub := range result.Subdomains {
			n := amassdns.RemoveAsteriskLabel(sub)
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				names = append(names, strings.ToLower(strings.TrimSpace(n)))
			}
		}

		for page := 2; page <= result.TotalPages; page++ {
			_ = j.rlimit.Wait(e.Session.Ctx())
			e.Session.NetSem().Acquire()

			ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)

			resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
				URL:    fmt.Sprintf("https://subdomains.jsmon.sh/api/domain/%s?page=%d", name, page),
				Header: amasshttp.Header{"Api-Key": []string{key}},
			})
			cancel()
			e.Session.NetSem().Release()
			if err != nil {
				break
			}

			if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
				break
			}

			for _, sub := range result.Subdomains {
				n := amassdns.RemoveAsteriskLabel(sub)
				if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
					names = append(names, strings.ToLower(strings.TrimSpace(n)))
				}
			}
		}
		break
	}

	return j.store(e, names)
}

func (j *jsmon) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, j.source, j.name, j.name+"-Handler")
}

func (j *jsmon) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, j.source)
}
