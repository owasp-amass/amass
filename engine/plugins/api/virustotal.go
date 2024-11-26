// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/dns"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type virusTotal struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewVirusTotal() et.Plugin {
	return &virusTotal{
		name:   "VirusTotal",
		rlimit: ratelimit.New(5, ratelimit.WithoutSlack),
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
		Plugin:       vt,
		Name:         name,
		Priority:     6,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     vt.check,
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
	fqdn, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
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

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), vt.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, vt.source, since) {
		names = append(names, vt.lookup(e, fqdn.Name, vt.source, since)...)
	} else {
		names = append(names, vt.query(e, fqdn.Name, vt.source, keys)...)
		support.MarkAssetMonitored(e.Session, e.Entity, vt.source)
	}

	if len(names) > 0 {
		vt.process(e, names, vt.source)
	}
	return nil
}

func (vt *virusTotal) lookup(e *et.Event, name string, src *et.Source, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), vt.source, since)
}

func (vt *virusTotal) query(e *et.Event, name string, src *et.Source, keys []string) []*dbt.Entity {
	var names []string

	for _, key := range keys {
		vt.rlimit.Take()
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
			if _, conf := e.Session.Scope().IsAssetInScope(&domain.FQDN{Name: nstr}, 0); conf > 0 {
				names = append(names, nstr)
			}
		}
		break
	}

	return vt.store(e, names, vt.source)
}

func (vt *virusTotal) store(e *et.Event, names []string, src *et.Source) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, vt.source, vt.name, vt.name+"-Handler")
}

func (vt *virusTotal) process(e *et.Event, assets []*dbt.Entity, src *et.Source) {
	support.ProcessFQDNsWithSource(e, assets, vt.source)
}
