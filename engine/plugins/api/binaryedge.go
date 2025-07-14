// Copyright © by Jeff Foley 2017-2025. All rights reserved.
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

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type binaryEdge struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewBinaryEdge() et.Plugin {
	limit := rate.Every(10 * time.Second)

	return &binaryEdge{
		name:   "BinaryEdge",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "BinaryEdge",
			Confidence: 80,
		},
	}
}

func (be *binaryEdge) Name() string {
	return be.name
}

func (be *binaryEdge) Start(r et.Registry) error {
	be.log = r.Log().WithGroup("plugin").With("name", be.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     be,
		Name:       be.name + "-Handler",
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   be.check,
	}); err != nil {
		return err
	}

	be.log.Info("Plugin started")
	return nil
}

func (be *binaryEdge) Stop() {
	be.log.Info("Plugin stopped")
}

func (be *binaryEdge) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(be.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), be.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, be.source, since) {
		names = append(names, be.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, be.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, be.source)
	}

	if len(names) > 0 {
		be.process(e, names)
	}
	return nil
}

func (be *binaryEdge) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), be.source, since)
}

func (be *binaryEdge) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

	pagenum := 1
loop:
	for _, key := range keys {
		for pagenum <= 500 {
			_ = be.rlimit.Wait(context.TODO())
			resp, err := http.RequestWebPage(context.TODO(), &http.Request{
				Header: http.Header{"X-KEY": []string{key}},
				URL:    "https://api.binaryedge.io/v2/query/domains/subdomain/" + name + "?page=" + strconv.Itoa(pagenum),
			})
			if err != nil || resp.Body == "" {
				break
			}

			var j struct {
				Results struct {
					Page     int      `json:"page"`
					PageSize int      `json:"pagesize"`
					Total    int      `json:"total"`
					Events   []string `json:"events"`
				} `json:"results"`
			}
			if err := json.Unmarshal([]byte("{\"results\":"+resp.Body+"}"), &j); err != nil {
				break
			}

			for _, n := range j.Results.Events {
				nstr := strings.ToLower(strings.TrimSpace(n))
				// if the subdomain is not in scope, skip it
				if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
					subs.Insert(nstr)
				}
			}

			if j.Results.Page > 0 && j.Results.Page <= 500 && j.Results.PageSize > 0 &&
				j.Results.Total > 0 && j.Results.Page <= (j.Results.Total/j.Results.PageSize) {
				pagenum++
			} else {
				break loop
			}
		}
	}

	return be.store(e, subs.Slice())
}

func (be *binaryEdge) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, be.source, be.name, be.name+"-Handler")
}

func (be *binaryEdge) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, be.source)
}
