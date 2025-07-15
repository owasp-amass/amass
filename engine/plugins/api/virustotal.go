// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/dns"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type virusTotal struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewVirusTotal() et.Plugin {
	limit := rate.Every(5 * time.Second)

	return &virusTotal{
		name:   "VirusTotal",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "VirusTotal",
			Confidence: 60,
		},
	}
}

func (vt *virusTotal) Name() string {
	return vt.name
}

func (vt *virusTotal) Start(r et.Registry) error {
	vt.log = r.Log().WithGroup("plugin").With("name", vt.name)

	name := vt.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     vt,
		Name:       name,
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   vt.check,
	}); err != nil {
		r.Log().Error(fmt.Sprintf("Failed to register a handler: %v", err),
			slog.Group("plugin", "name", vt.name, "handler", name))
		return err
	}

	vt.log.Info("Plugin started")
	return nil
}

func (vt *virusTotal) Stop() {
	vt.log.Info("Plugin stopped")
}

func (vt *virusTotal) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	ds := e.Session.Config().GetDataSourceConfig(vt.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), vt.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, vt.source, since) {
		names = append(names, vt.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, vt.query(e, fqdn.Name, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, vt.source)
	}

	if len(names) > 0 {
		vt.process(e, names)
	}
	return nil
}

func (vt *virusTotal) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), vt.source, since)
}

func (vt *virusTotal) query(e *et.Event, name string, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		_ = vt.rlimit.Wait(context.TODO())
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{
			URL: "https://www.virustotal.com/vtapi/v2/domain/report?domain=" + name + "&apikey=" + key,
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
			nstr := strings.ToLower(strings.TrimSpace(dns.RemoveAsteriskLabel(sub)))
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
				names = append(names, nstr)
			}
		}
		break
	}

	return vt.store(e, names)
}

func (vt *virusTotal) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, vt.source, vt.name, vt.name+"-Handler")
}

func (vt *virusTotal) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, vt.source)
}
