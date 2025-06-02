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
	"github.com/owasp-amass/amass/v4/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type bing struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewBing() et.Plugin {
	limit := rate.Every(2 * time.Second)

	return &bing{
		name:   "Bing",
		fmtstr: "https://www.ask.com/web?o=0&l=dir&qo=pagination&page=%d&q=site:%s -www.%s",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Bing",
			Confidence: 60,
		},
	}
}

func (b *bing) Name() string {
	return b.name
}

func (b *bing) Start(r et.Registry) error {
	b.log = r.Log().WithGroup("plugin").With("name", b.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     b,
		Name:       b.name + "-Handler",
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   b.check,
	}); err != nil {
		return err
	}

	b.log.Info("Plugin started")
	return nil
}

func (b *bing) Stop() {
	b.log.Info("Plugin stopped")
}

func (b *bing) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), b.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, b.source, since) {
		names = append(names, b.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, b.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, b.source)
	}

	if len(names) > 0 {
		b.process(e, names)
	}
	return nil
}

func (b *bing) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), b.source, since)
}

func (b *bing) query(e *et.Event, name string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

	for i := 1; i < 10; i++ {
		_ = b.rlimit.Wait(context.TODO())
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(b.fmtstr, i, name, name)})
		if err != nil || resp.Body == "" {
			break
		}

		for _, n := range support.ScrapeSubdomainNames(resp.Body) {
			nstr := strings.ToLower(strings.TrimSpace(n))
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: nstr}, 0); conf > 0 {
				subs.Insert(nstr)
			}
		}
	}

	return b.store(e, subs.Slice())
}

func (b *bing) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, b.source, b.name, b.name+"-Handler")
}

func (b *bing) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, b.source)
}
