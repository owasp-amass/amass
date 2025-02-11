// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/url"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/org"
	"go.uber.org/ratelimit"
)

type gleif struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewGLEIF() et.Plugin {
	return &gleif{
		name:   "GLEIF",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "GLEIF",
			Confidence: 100,
		},
	}
}

func (g *gleif) Name() string {
	return g.name
}

func (g *gleif) Start(r et.Registry) error {
	g.log = r.Log().WithGroup("plugin").With("name", g.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       g,
		Name:         g.name + "-Handler",
		Priority:     6,
		MaxInstances: 2,
		Transforms: []string{
			string(oam.Identifier),
			string(oam.Organization),
		},
		EventType: oam.Organization,
		Callback:  g.check,
	}); err != nil {
		return err
	}

	g.log.Info("Plugin started")
	return nil
}

func (g *gleif) Stop() {
	g.log.Info("Plugin stopped")
}

func (g *gleif) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*org.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Organization), string(oam.Organization), g.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, g.source, since) {
		names = append(names, g.lookup(e, o, g.source, since)...)
	} else {
		names = append(names, g.query(e, o, g.source)...)
		support.MarkAssetMonitored(e.Session, e.Entity, g.source)
	}

	if len(names) > 0 {
		g.process(e, names, g.source)
	}
	return nil
}

func (g *gleif) lookup(e *et.Event, o *org.Organization, src *et.Source, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, o.Key(), string(oam.FQDN), g.source, since)
}

type gleifFuzzy struct {
	Data []struct {
		Type       string `json:"type"`
		Attributes struct {
			Value string `json:"value"`
		} `json:"attributes"`
		Relationships struct {
			LEIRecords struct {
				Data struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"data"`
				Links struct {
					Related string `json:"related"`
				} `json:"links"`
			} `json:"lei-records"`
		} `json:"relationships"`
	} `json:"data"`
}

func (g *gleif) query(e *et.Event, o *org.Organization, src *et.Source) []*dbt.Entity {
	u := "https://api.gleif.org/api/v1/fuzzycompletions?field=fulltext&q=" + url.QueryEscape(o.Name)

	g.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		return nil
	}

	var result gleifFuzzy
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil || len(result.Data) == 0 {
		return nil
	}

	return g.store(e, &result, g.source)
}

func (g *gleif) store(e *et.Event, fuzzy *gleifFuzzy, src *et.Source) []*dbt.Entity {
	return nil
}

func (g *gleif) process(e *et.Event, assets []*dbt.Entity, src *et.Source) {
	return
}
