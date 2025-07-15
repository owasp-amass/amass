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
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type rapidDNS struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewRapidDNS() et.Plugin {
	limit := rate.Every(5 * time.Second)

	return &rapidDNS{
		name:   "RapidDNS",
		fmtstr: "https://rapiddns.io/subdomain/%s?full=1",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "RapidDNS",
			Confidence: 70,
		},
	}
}

func (rd *rapidDNS) Name() string {
	return rd.name
}

func (rd *rapidDNS) Start(r et.Registry) error {
	rd.log = r.Log().WithGroup("plugin").With("name", rd.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     rd,
		Name:       rd.name + "-Handler",
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   rd.check,
	}); err != nil {
		return err
	}

	rd.log.Info("Plugin started")
	return nil
}

func (rd *rapidDNS) Stop() {
	rd.log.Info("Plugin stopped")
}

func (rd *rapidDNS) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), rd.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, rd.source, since) {
		names = append(names, rd.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, rd.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, rd.source)
	}

	if len(names) > 0 {
		rd.process(e, names)
	}
	return nil
}

func (rd *rapidDNS) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), rd.source, since)
}

func (rd *rapidDNS) query(e *et.Event, name string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

	_ = rd.rlimit.Wait(context.TODO())
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(rd.fmtstr, name)})
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

	return rd.store(e, subs.Slice())
}

func (rd *rapidDNS) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, rd.source, rd.name, rd.name+"-Handler")
}

func (rd *rapidDNS) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, rd.source)
}
