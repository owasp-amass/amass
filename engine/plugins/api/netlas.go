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
	"net/url"
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

type netlas struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewNetlas() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &netlas{
		name:   "Netlas",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Netlas",
			Confidence: 80,
		},
	}
}

func (n *netlas) Name() string {
	return n.name
}

func (n *netlas) Start(r et.Registry) error {
	n.log = r.Log().WithGroup("plugin").With("name", n.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       n,
		Name:         n.name + "-Handler",
		Position:     36,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     n.check,
	}); err != nil {
		return err
	}

	n.log.Info("Plugin started")
	return nil
}

func (n *netlas) Stop() {
	if n.log != nil {
		n.log.Info("Plugin stopped")
	}
}

func (n *netlas) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(n.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), n.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, n.source, since) {
		names = append(names, n.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, n.source)
	}

	if len(names) > 0 {
		n.process(e, names)
	}
	return nil
}

func (n *netlas) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

	start := 0
loop:
	for _, key := range keys {
		for start <= 500 {
			_ = n.rlimit.Wait(e.Session.Ctx())
			e.Session.NetSem().Acquire()

			ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
			reqURL := fmt.Sprintf("https://app.netlas.io/api/domains/?q=%s&start=%d",
				url.QueryEscape("domain:*."+name), start)
			resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
				Header: amasshttp.Header{
					"Accept":    []string{"application/json"},
					"X-API-Key": []string{key},
				},
				URL: reqURL,
			})
			cancel()
			e.Session.NetSem().Release()
			if err != nil || resp.Body == "" {
				break
			}

			var result struct {
				Count int `json:"count"`
				Items []struct {
					ID   string `json:"id"`
					Data struct {
						Domain string `json:"domain"`
					} `json:"data"`
				} `json:"items"`
			}
			if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
				break
			}

			if len(result.Items) == 0 {
				break
			}

			for _, item := range result.Items {
				d := item.Data.Domain
				if d == "" {
					d = item.ID
				}
				d = amassdns.RemoveAsteriskLabel(d)
				if !strings.HasSuffix(d, "."+name) && d != name {
					d = d + "." + name
				}
				d = strings.ToLower(strings.Trim(d, "."))
				if d == "" {
					continue
				}

				if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: d}, 0); conf > 0 {
					subs.Insert(d)
				}
			}

			start += len(result.Items)
			if start >= result.Count || len(result.Items) < 20 {
				break loop
			}
		}
	}

	return n.store(e, subs.Slice())
}

func (n *netlas) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, n.source, n.name, n.name+"-Handler")
}

func (n *netlas) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, n.source)
}
