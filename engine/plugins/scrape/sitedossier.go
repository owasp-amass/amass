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

type siteDossier struct {
	name   string
	fmtstr string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewSiteDossier() et.Plugin {
	limit := rate.Every(4 * time.Second)

	return &siteDossier{
		name:   "SiteDossier",
		fmtstr: "http://www.sitedossier.com/parentdomain/%s/%d",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "SiteDossier",
			Confidence: 60,
		},
	}
}

func (sd *siteDossier) Name() string {
	return sd.name
}

func (sd *siteDossier) Start(r et.Registry) error {
	sd.log = r.Log().WithGroup("plugin").With("name", sd.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       sd,
		Name:         sd.name + "-Handler",
		Priority:     7,
		MaxInstances: 10,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     sd.check,
	}); err != nil {
		return err
	}

	sd.log.Info("Plugin started")
	return nil
}

func (sd *siteDossier) Stop() {
	sd.log.Info("Plugin stopped")
}

func (sd *siteDossier) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), sd.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, sd.source, since) {
		names = append(names, sd.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, sd.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, sd.source)
	}

	if len(names) > 0 {
		sd.process(e, names)
	}
	return nil
}

func (sd *siteDossier) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), sd.source, since)
}

func (sd *siteDossier) query(e *et.Event, name string) []*dbt.Entity {
	subs := stringset.New()
	defer subs.Close()

	for i := 1; i < 20; i++ {
		_ = sd.rlimit.Wait(context.TODO())
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: fmt.Sprintf(sd.fmtstr, name, i)})
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

	return sd.store(e, subs.Slice())
}

func (sd *siteDossier) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, sd.source, sd.name, sd.name+"-Handler")
}

func (sd *siteDossier) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, sd.source)
}
