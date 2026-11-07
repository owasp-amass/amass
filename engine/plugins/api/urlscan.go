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

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type urlScan struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

// NewURLScan returns an initialized URLScan plugin instance.
func NewURLScan() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &urlScan{
		name:   "URLScan",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "URLScan",
			Confidence: 80,
		},
	}
}

func (u *urlScan) Name() string {
	return u.name
}

func (u *urlScan) Start(r et.Registry) error {
	u.log = r.Log().WithGroup("plugin").With("name", u.name)

	name := u.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       u,
		Name:         name,
		Position:     26,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     u.check,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", u.name, "handler", name))
		return err
	}

	u.log.Info("Plugin started")
	return nil
}

func (u *urlScan) Stop() {
	u.log.Info("Plugin stopped")
}

func (u *urlScan) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	var keys []string
	if ds := e.Session.Config().GetDataSourceConfig(u.name); ds != nil {
		for _, cr := range ds.Creds {
			if cr != nil && cr.Apikey != "" {
				keys = append(keys, cr.Apikey)
			}
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), u.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, u.source, since) {
		names = append(names, u.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, u.source)
	}

	if len(names) > 0 {
		u.process(e, names)
	}
	return nil
}

func (u *urlScan) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

	headers := amasshttp.Header{}
	if len(keys) > 0 {
		headers["API-Key"] = []string{keys[0]}
	}

	_ = u.rlimit.Wait(e.Session.Ctx())
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL:    "https://urlscan.io/api/v1/search/?q=domain:" + name + "&size=100",
		Header: headers,
	})
	e.Session.NetSem().Release()
	if err != nil || resp.Body == "" {
		return nil
	}

	var result struct {
		Results []struct {
			Page struct {
				Domain string `json:"domain"`
			} `json:"page"`
			Task struct {
				Domain string `json:"domain"`
			} `json:"task"`
		} `json:"results"`
	}

	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil
	}

	for _, item := range result.Results {
		for _, domain := range []string{item.Page.Domain, item.Task.Domain} {
			if domain == "" {
				continue
			}
			nstr := strings.ToLower(strings.TrimSpace(amassdns.RemoveAsteriskLabel(domain)))
			if nstr == "" {
				continue
			}
			// if the subdomain is in scope, add it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
				subs.Insert(nstr)
			}
		}
	}

	return u.store(e, subs.Slice())
}

func (u *urlScan) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, u.source, u.name, u.name+"-Handler")
}

func (u *urlScan) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, u.source)
}
