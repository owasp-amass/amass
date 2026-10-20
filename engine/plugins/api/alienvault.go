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

type alienVault struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewAlienVault() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &alienVault{
		name:   "AlienVault",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "AlienVault",
			Confidence: 80,
		},
	}
}

func (a *alienVault) Name() string {
	return a.name
}

func (a *alienVault) Start(r et.Registry) error {
	a.log = r.Log().WithGroup("plugin").With("name", a.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       a,
		Name:         a.name + "-Handler",
		Position:     24,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     a.check,
	}); err != nil {
		return err
	}

	a.log.Info("Plugin started")
	return nil
}

func (a *alienVault) Stop() {
	a.log.Info("Plugin stopped")
}

func (a *alienVault) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	var keys []string
	ds := e.Session.Config().GetDataSourceConfig(a.name)
	if ds != nil {
		for _, cred := range ds.Creds {
			if cred != nil && cred.Apikey != "" {
				keys = append(keys, cred.Apikey)
			}
		}
	}
	// Fallback to unauthenticated access if no API keys are configured
	if len(keys) == 0 {
		keys = append(keys, "")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), a.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if !support.AssetMonitoredWithinTTL(e.Session, e.Entity, a.source, since) {
		names = append(names, a.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, a.source)
	}

	if len(names) > 0 {
		a.process(e, names)
	}
	return nil
}

func (a *alienVault) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = a.rlimit.Wait(e.Session.Ctx())
		e.Session.NetSem().Acquire()

		ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)

		headers := make(amasshttp.Header)
		if key != "" {
			headers["X-OTX-API-KEY"] = []string{key}
		}

		resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
			URL:    "https://otx.alienvault.com/api/v1/indicators/domain/" + name + "/passive_dns",
			Header: headers,
		})
		e.Session.NetSem().Release()
		cancel()

		if err != nil || resp.Body == "" {
			continue
		}

		var result struct {
			PassiveDNS []struct {
				Hostname string `json:"hostname"`
			} `json:"passive_dns"`
		}

		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		for _, record := range result.PassiveDNS {
			n := strings.ToLower(strings.TrimSpace(amassdns.RemoveAsteriskLabel(record.Hostname)))
			if n == "" {
				continue
			}
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				names = append(names, n)
			}
		}
		break
	}

	return a.store(e, names)
}

func (a *alienVault) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, a.source, a.name, a.name+"-Handler")
}

func (a *alienVault) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, a.source)
}
