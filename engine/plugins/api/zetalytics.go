// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/dns"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type zetalytics struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewZetalytics() et.Plugin {
	return &zetalytics{
		name:   "ZETAlytics",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "ZETAlytics",
			Confidence: 100,
		},
	}
}

func (z *zetalytics) Name() string {
	return z.name
}

func (z *zetalytics) Start(r et.Registry) error {
	z.log = r.Log().WithGroup("plugin").With("name", z.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       z,
		Name:         z.name + "-Handler",
		Priority:     6,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     z.check,
	}); err != nil {
		return err
	}

	z.log.Info("Plugin started")
	return nil
}

func (z *zetalytics) Stop() {
	z.log.Info("Plugin stopped")
}

func (z *zetalytics) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(z.name)
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


	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), z.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, z.source, since) {
		names = append(names, z.lookup(e, fqdn.Name, z.source, since)...)
	} else {
		names = append(names, z.query(e, fqdn.Name, z.source, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, z.source)
	}

	if len(names) > 0 {
		z.process(e, names, z.source)
	}
	return nil
}

func (z *zetalytics) lookup(e *et.Event, name string, src *et.Source, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), z.source, since)
}

func (z *zetalytics) query(e *et.Event, name string, src *et.Source, keys []string) []*dbt.Entity {
	names := support.NewFQDNFilter()
	defer names.Close()

	for _, key := range keys {
		start := time.Now().Add((time.Hour * 24) * -90).Unix() // The epoch 90 days ago
		url := "https://zonecruncher.com/api/v1/subdomains?q=" + name +
			"&token=" + key + "&tsfield=last_seen&start=" + strconv.FormatInt(start, 10)

		z.rlimit.Take()
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: url})
		if err != nil || resp.Body == "" {
			continue
		}

		var result struct {
			Total      int `json:"total"`
			Subdomains []struct {
				FQDN string `json:"qname"`
				//FirstSeen string `json:"first_seen"`
				//LastSeen  string `json:"last_seen"`
			} `json:"results"`
			Msg string `json:"msg"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &result); err != nil || result.Total == 0 {
			break
		}

		for _, s := range result.Subdomains {
			name := strings.ToLower(strings.TrimSpace(dns.RemoveAsteriskLabel(http.CleanName(s.FQDN))))
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: name}, 0); conf > 0 {
				names.Insert(name)
			}
		}
		break
	}

	names.Prune(1000)
	return z.store(e, names.Slice(), z.source)
}

func (z *zetalytics) store(e *et.Event, names []string, src *et.Source) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, z.source, z.name, z.name+"-Handler")
}

func (z *zetalytics) process(e *et.Event, assets []*dbt.Entity, src *et.Source) {
	support.ProcessFQDNsWithSource(e, assets, z.source)
}
