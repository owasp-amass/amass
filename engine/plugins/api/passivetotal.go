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

	"github.com/owasp-amass/amass/v4/config"
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

type passiveTotal struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *source.Source
}

func NewPassiveTotal() et.Plugin {
	return &passiveTotal{
		name:   "PassiveTotal",
		rlimit: ratelimit.New(10, ratelimit.WithoutSlack),
		source: &source.Source{
			Name:       "PassiveTotal",
			Confidence: 30,
		},
	}
}

func (pt *passiveTotal) Name() string {
	return pt.name
}

func (pt *passiveTotal) Start(r et.Registry) error {
	pt.log = r.Log().WithGroup("plugin").With("name", pt.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       pt,
		Name:         pt.name + "-Handler",
		Priority:     6,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     pt.check,
	}); err != nil {
		return err
	}

	pt.log.Info("Plugin started")
	return nil
}

func (pt *passiveTotal) Stop() {
	pt.log.Info("Plugin stopped")
}

func (pt *passiveTotal) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(pt.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	src := support.GetSource(e.Session, pt.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), pt.name)
	if err != nil {
		return err
	}

	var names []*dbt.Asset
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		names = append(names, pt.lookup(e, fqdn.Name, src, since)...)
	} else {
		names = append(names, pt.query(e, fqdn.Name, src, ds)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(names) > 0 {
		pt.process(e, names, src)
	}
	return nil
}

func (pt *passiveTotal) lookup(e *et.Event, name string, src *dbt.Asset, since time.Time) []*dbt.Asset {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), src, since)
}

func (pt *passiveTotal) query(e *et.Event, name string, src *dbt.Asset, ds *config.DataSource) []*dbt.Asset {
	names := support.NewFQDNFilter()
	defer names.Close()

	var lastid string
loop:
	for _, cr := range ds.Creds {
		for lastid != "" {
			if cr == nil || cr.Username == "" || cr.Apikey == "" {
				continue
			}

			url := "https://api.riskiq.net/pt/v2/enrichment/subdomains?query=" + name
			if lastid != "" {
				url += "&lastId=" + lastid
			}
			pt.rlimit.Take()
			resp, err := http.RequestWebPage(context.TODO(), &http.Request{
				URL: url,
				Auth: &http.BasicAuth{
					Username: cr.Username,
					Password: cr.Apikey,
				},
			})
			if err != nil || resp.Body == "" {
				continue
			}

			var result struct {
				Success    bool     `json:"success"`
				Subdomains []string `json:"subdomains"`
				LastID     string   `json:"lastId"`
			}
			if err := json.Unmarshal([]byte(resp.Body), &result); err != nil || !result.Success {
				break
			}

			for _, sub := range result.Subdomains {
				n := dns.RemoveAsteriskLabel(http.CleanName(sub + "." + name))
				// if the subdomain is not in scope, skip it
				if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: n}, 0); conf > 0 {
					names.Insert(n)
				}
			}

			lastid = result.LastID
			if lastid == "" {
				break loop
			}
		}
	}

	names.Prune(1000)
	return pt.store(e, names.Slice(), src)
}

func (pt *passiveTotal) store(e *et.Event, names []string, src *dbt.Asset) []*dbt.Asset {
	return support.StoreFQDNsWithSource(e.Session, names, src, pt.name, pt.name+"-Handler")
}

func (pt *passiveTotal) process(e *et.Event, assets []*dbt.Asset, src *dbt.Asset) {
	support.ProcessFQDNsWithSource(e, assets, src)
}
