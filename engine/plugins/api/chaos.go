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
	"github.com/owasp-amass/amass/v4/utils/net/dns"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type chaos struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewChaos() et.Plugin {
	limit := rate.Every(10 * time.Second)

	return &chaos{
		name:   "Chaos",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Chaos",
			Confidence: 80,
		},
	}
}

func (c *chaos) Name() string {
	return c.name
}

func (c *chaos) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     c,
		Name:       c.name + "-Handler",
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *chaos) Stop() {
	c.log.Info("Plugin stopped")
}

func (c *chaos) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(c.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), c.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		names = append(names, c.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, c.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, c.source)
	}

	if len(names) > 0 {
		c.process(e, names)
	}
	return nil
}

func (c *chaos) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), c.source, since)
}

func (c *chaos) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = c.rlimit.Wait(context.TODO())
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{
			URL:    "https://dns.projectdiscovery.io/dns/" + name + "/subdomains",
			Header: http.Header{"Authorization": []string{key}},
		})
		if err != nil {
			continue
		}

		var result struct {
			Subdomains []string `json:"subdomains"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
			continue
		}

		for _, sub := range result.Subdomains {
			n := dns.RemoveAsteriskLabel(sub + "." + name)
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				names = append(names, strings.ToLower(strings.TrimSpace(n)))
			}
		}
		break
	}

	return c.store(e, names)
}

func (c *chaos) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, c.source, c.name, c.name+"-Handler")
}

func (c *chaos) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, c.source)
}
