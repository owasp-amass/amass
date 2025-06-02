// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/internal/net/dns"
	"github.com/owasp-amass/amass/v4/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type securityTrails struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewSecurityTrails() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &securityTrails{
		name:   "SecurityTrails",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "SecurityTrails",
			Confidence: 80,
		},
	}
}

func (st *securityTrails) Name() string {
	return st.name
}

func (st *securityTrails) Start(r et.Registry) error {
	st.log = r.Log().WithGroup("plugin").With("name", st.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     st,
		Name:       st.name + "-Handler",
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   st.check,
	}); err != nil {
		return err
	}

	st.log.Info("Plugin started")
	return nil
}

func (st *securityTrails) Stop() {
	st.log.Info("Plugin stopped")
}

func (st *securityTrails) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(st.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), st.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, st.source, since) {
		names = append(names, st.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, st.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, st.source)
	}

	if len(names) > 0 {
		st.process(e, names)
	}
	return nil
}

func (st *securityTrails) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), st.source, since)
}

func (st *securityTrails) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = st.rlimit.Wait(context.TODO())
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{
			URL:    "https://api.securitytrails.com/v1/domain/" + name + "/subdomains",
			Header: http.Header{"APIKEY": []string{key}},
		})
		if err != nil || resp.Body == "" {
			continue
		}

		var result struct {
			Subdomains []string `json:"subdomains"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		for _, sub := range result.Subdomains {
			nstr := strings.ToLower(strings.TrimSpace(dns.RemoveAsteriskLabel(sub + "." + name)))
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
				names = append(names, nstr)
			}
		}
		break
	}

	return st.store(e, names)
}

func (st *securityTrails) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, st.source, st.name, st.name+"-Handler")
}

func (st *securityTrails) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, st.source)
}
