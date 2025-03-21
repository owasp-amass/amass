// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type duckDuckGo struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewDuckDuckGo() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &duckDuckGo{
		name:   "DuckDuckGo",
		fmtstr: "https://html.duckduckgo.com/html/?q=site:%s -site:www.%s",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "DuckDuckGo",
			Confidence: 60,
		},
	}
}

func (d *duckDuckGo) Name() string {
	return d.name
}

func (d *duckDuckGo) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.name + "-Handler",
		Priority:     7,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *duckDuckGo) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *duckDuckGo) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), d.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		names = append(names, d.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, d.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, d.source)
	}

	if len(names) > 0 {
		d.process(e, names)
	}
	return nil
}

func (d *duckDuckGo) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), d.source, since)
}

func (d *duckDuckGo) query(e *et.Event, name string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

	_ = d.rlimit.Wait(context.TODO())
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(d.fmtstr, name, name)})
	if err != nil || resp.Body == "" {
		return nil
	}

	for _, n := range support.ScrapeSubdomainNames(resp.Body) {
		nstr := strings.ToLower(strings.TrimSpace(n))
		// if the subdomain is not in scope, skip it
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
			subs.Insert(nstr)
		}
	}

	return d.store(e, subs.Slice())
}

func (d *duckDuckGo) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, d.source, d.name, d.name+"-Handler")
}

func (d *duckDuckGo) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, d.source)
}
