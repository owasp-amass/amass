// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/csv"
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type hackerTarget struct {
	name   string
	url    string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewHackerTarget() et.Plugin {
	return &hackerTarget{
		name:   "HackerTarget",
		url:    "https://api.hackertarget.com/hostsearch/?q=",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "HackerTarget",
			Confidence: 80,
		},
	}
}

func (ht *hackerTarget) Name() string {
	return ht.name
}

func (ht *hackerTarget) Start(r et.Registry) error {
	ht.log = r.Log().WithGroup("plugin").With("name", ht.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       ht,
		Name:         ht.name + "-Handler",
		Priority:     5,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     ht.check,
	}); err != nil {
		return err
	}

	ht.log.Info("Plugin started")
	return nil
}

func (ht *hackerTarget) Stop() {
	ht.log.Info("Plugin stopped")
}

func (ht *hackerTarget) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	src := support.GetSource(e.Session, ht.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), ht.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		names = append(names, ht.lookup(e, fqdn.Name, src, since)...)
	} else {
		names = append(names, ht.query(e, fqdn.Name, src)...)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if len(names) > 0 {
		ht.process(e, names, src)
	}
	return nil
}

func (ht *hackerTarget) lookup(e *et.Event, name string, src *et.Source, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), src, since)
}

func (ht *hackerTarget) query(e *et.Event, name string, src *et.Source) []*dbt.Entity {
	ht.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: ht.url + name})
	if err != nil {
		return nil
	}

	var names []string
	if records, err := csv.NewReader(strings.NewReader(resp.Body)).ReadAll(); err == nil {
		for _, record := range records {
			if len(record) < 2 {
				continue
			}
			// if the subdomain is not in scope, skip it
			n := strings.ToLower(strings.TrimSpace(record[0]))
			if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: n}, 0); conf > 0 {
				names = append(names, n)
			}
		}
	}

	return ht.store(e, names, src)
}

func (ht *hackerTarget) store(e *et.Event, names []string, src *et.Source) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, src, ht.name, ht.name+"-Handler")
}

func (ht *hackerTarget) process(e *et.Event, assets []*dbt.Entity, src *et.Source) {
	support.ProcessFQDNsWithSource(e, assets, src)
}
