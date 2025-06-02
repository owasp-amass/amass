// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/internal/net/dns"
	"github.com/owasp-amass/amass/v4/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"golang.org/x/time/rate"
)

type wayback struct {
	name   string
	URL    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewWayback() et.Plugin {
	limit := rate.Every(5 * time.Second)

	return &wayback{
		name:   "Wayback",
		URL:    "https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original&output=json&collapse=urlkey&url=",
		rlimit: rate.NewLimiter(limit, 1),
		source: &et.Source{
			Name:       "Wayback",
			Confidence: 80,
		},
	}
}

func (w *wayback) Name() string {
	return w.name
}

func (w *wayback) Start(r et.Registry) error {
	w.log = r.Log().WithGroup("plugin").With("name", w.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:     w,
		Name:       w.name + "-Handler",
		Priority:   9,
		Transforms: []string{string(oam.FQDN)},
		EventType:  oam.FQDN,
		Callback:   w.check,
	}); err != nil {
		return err
	}

	w.log.Info("Plugin started")
	return nil
}

func (w *wayback) Stop() {
	w.log.Info("Plugin stopped")
}

func (w *wayback) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasSLDInScope(e) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), w.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, w.source, since) {
		names = append(names, w.lookup(e, fqdn.Name, since)...)
	} else {
		names = append(names, w.query(e, fqdn.Name)...)
		support.MarkAssetMonitored(e.Session, e.Entity, w.source)
	}

	if len(names) > 0 {
		w.process(e, names)
	}
	return nil
}

func (w *wayback) lookup(e *et.Event, name string, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.FQDN), w.source, since)
}

func (w *wayback) query(e *et.Event, name string) []*dbt.Entity {
	_ = w.rlimit.Wait(context.TODO())
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: w.URL + name})
	if err != nil {
		return nil
	}

	subs := stringset.New()
	defer subs.Close()

	var urls [][]string
	if err := json.Unmarshal([]byte(resp.Body), &urls); err != nil {
		return nil
	}

	for _, url := range urls {
		if len(url) != 1 {
			continue
		}
		u := url[0]

		if n := dns.AnySubdomainRegex().FindString(u); n != "" {
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				subs.Insert(n)
			}
		}
	}

	return w.store(e, subs.Slice())
}

func (w *wayback) store(e *et.Event, names []string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, names, w.source, w.name, w.name+"-Handler")
}

func (w *wayback) process(e *et.Event, assets []*dbt.Entity) {
	support.ProcessFQDNsWithSource(e, assets, w.source)
}
