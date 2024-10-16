// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
	"github.com/owasp-amass/amass/v4/utils/net/dns"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/source"
	"go.uber.org/ratelimit"
)

type leakix struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *source.Source
}

func NewLeakIX() et.Plugin {
	return &leakix{
		name:   "LeakIX",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &source.Source{
			Name:       "LeakIX",
			Confidence: 80,
		},
	}
}

func (ix *leakix) Name() string {
	return ix.name
}

func (ix *leakix) Start(r et.Registry) error {
	ix.log = r.Log().WithGroup("plugin").With("name", ix.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       ix,
		Name:         ix.name + "-Handler",
		Priority:     5,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     ix.check,
	}); err != nil {
		return err
	}

	ix.log.Info("Plugin started")
	return nil
}

func (ix *leakix) Stop() {
	ix.log.Info("Plugin stopped")
}

func (ix *leakix) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(ix.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	src := support.GetSource(e.Session, ix.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), ix.name)
	if err != nil {
		return err
	}

	var names []*dbt.Asset
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		names = append(names, ix.lookup(e, fqdn.Name, src, since)...)
	} else {
		names = append(names, ix.query(e, fqdn.Name, src, keys)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(names) > 0 {
		ix.process(e, names, src)
	}
	return nil
}

func (ix *leakix) lookup(e *et.Event, name string, src *dbt.Asset, since time.Time) []*dbt.Asset {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), src, since)
}

func (ix *leakix) query(e *et.Event, name string, src *dbt.Asset, keys []string) []*dbt.Asset {
	var names []string

	for _, key := range keys {
		ix.rlimit.Take()
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{
			URL:    "https://leakix.net/api/subdomains/" + name,
			Header: http.Header{"Accept": []string{"application/json"}, "api-key": []string{key}},
		})
		if err != nil || resp.Body == "" {
			continue
		}

		var result struct {
			Subdomains []struct {
				FQDN string `json:"subdomain"`
			} `json:"subdomains"`
		}
		if err := json.Unmarshal([]byte("{\"subdomains\":"+resp.Body+"}"), &result); err != nil {
			continue
		}

		for _, s := range result.Subdomains {
			name := strings.ToLower(strings.TrimSpace(dns.RemoveAsteriskLabel(s.FQDN)))
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: name}, 0); conf > 0 {
				names = append(names, name)
			}
		}
		break
	}

	return ix.store(e, names, src)
}

func (ix *leakix) store(e *et.Event, names []string, src *dbt.Asset) []*dbt.Asset {
	return support.StoreFQDNsWithSource(e.Session, names, src, ix.name, ix.name+"-Handler")
}

func (ix *leakix) process(e *et.Event, assets []*dbt.Asset, src *dbt.Asset) {
	support.ProcessFQDNsWithSource(e, assets, src)
}
