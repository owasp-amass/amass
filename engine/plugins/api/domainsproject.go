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

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type domainsProject struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewDomainsProject() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &domainsProject{
		name:   "DomainsProject",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "DomainsProject",
			Confidence: 80,
		},
	}
}

func (dp *domainsProject) Name() string {
	return dp.name
}

func (dp *domainsProject) Start(r et.Registry) error {
	dp.log = r.Log().WithGroup("plugin").With("name", dp.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     dp,
		Name:       dp.name + "-Handler",
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   dp.check,
	}); err != nil {
		return err
	}

	dp.log.Info("Plugin started")
	return nil
}

func (dp *domainsProject) Stop() {
	dp.log.Info("Plugin stopped")
}

func (dp *domainsProject) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(dp.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), dp.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, dp.source, since) {
		names = append(names, dp.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, dp.query(e, fqdn.Name, ds)...)
		support.MarkAssetMonitored(e.Session, e.Entity, dp.source)
	}

	if len(names) > 0 {
		dp.process(e, names)
	}
	return nil
}

func (dp *domainsProject) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), dp.source, since)
}

func (dp *domainsProject) query(e *et.Event, name string, ds *config.DataSource) []*dbt.Entity {
	var names []string

	for _, cr := range ds.Creds {
		if cr == nil || cr.Username == "" || cr.Password == "" {
			continue
		}

		_ = dp.rlimit.Wait(context.TODO())
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{
			URL:    "https://api.domainsproject.org/api/tld/search?domain=" + name,
			Header: http.Header{"Accept": []string{"application/json"}},
			Auth: &http.BasicAuth{
				Username: cr.Username,
				Password: cr.Password,
			},
		})
		if err != nil || resp.Body == "" {
			continue
		}

		var result struct {
			Domains []string `json:"domains"`
			Error   string   `json:"error"`
		}

		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		for _, s := range result.Domains {
			subdomain := strings.ToLower(strings.TrimSpace(dns.RemoveAsteriskLabel(s)))
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: subdomain}, 0); conf > 0 {
				names = append(names, subdomain)
			}
		}
		break
	}

	return dp.store(e, names)
}

func (dp *domainsProject) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, dp.source, dp.name, dp.name+"-Handler")
}

func (dp *domainsProject) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, dp.source)
}
