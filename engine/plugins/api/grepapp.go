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
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"go.uber.org/ratelimit"
)

type grepApp struct {
	name   string
	log    *slog.Logger
	rlimit ratelimit.Limiter
	source *et.Source
}

func NewGrepApp() et.Plugin {
	return &grepApp{
		name:   "Grep.App",
		rlimit: ratelimit.New(2, ratelimit.WithoutSlack),
		source: &et.Source{
			Name:       "Grep.App",
			Confidence: 50,
		},
	}
}

func (g *grepApp) Name() string {
	return g.name
}

func (g *grepApp) Start(r et.Registry) error {
	g.log = r.Log().WithGroup("plugin").With("name", g.name)

	name := g.name + "-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       g,
		Name:         name,
		Priority:     7,
		MaxInstances: 10,
		Transforms:   []string{string(oam.EmailAddress)},
		EventType:    oam.FQDN,
		Callback:     g.check,
	}); err != nil {
		return err
	}

	g.log.Info("Plugin started")
	return nil
}

func (g *grepApp) Stop() {
	g.log.Info("Plugin stopped")
}

func (g *grepApp) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if f, ok := a.(*domain.FQDN); !ok || f == nil || !strings.EqualFold(fqdn.Name, f.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.EmailAddress), g.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, g.source, since) {
		names = append(names, g.lookup(e, fqdn.Name, g.source, since)...)
	} else {
		names = append(names, g.query(e, fqdn.Name, g.source)...)
		support.MarkAssetMonitored(e.Session, e.Entity, g.source)
	}

	if len(names) > 0 {
		g.process(e, names, g.source)
	}
	return nil
}
func (g *grepApp) lookup(e *et.Event, name string, src *et.Source, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, name, string(oam.EmailAddress), g.source, since)
}

func (g *grepApp) query(e *et.Event, name string, src *et.Source) []*dbt.Entity {
	newdlt := strings.ReplaceAll(name, ".", `\.`)
	escapedQuery := url.QueryEscape("([a-zA-Z0-9._-]+)@" + newdlt)
	re := regexp.MustCompile(`([a-zA-Z0-9._-]+)@` + newdlt)

	emails := stringset.New()
	defer emails.Close()

	cont := true
	for page := 1; cont; page++ {
		g.rlimit.Take()
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{
			URL: fmt.Sprintf("https://grep.app/api/search?page=%s&q=%s&regexp=true", strconv.Itoa(page), escapedQuery),
		})
		if err != nil {
			break
		}

		var response struct {
			Facets struct {
				Hits []struct {
					Content struct {
						Snippet string `json:"snippet"`
					} `json:"content"`
				} `json:"hits"`
				Total int `json:"total"`
			} `json:"facets"`
		}
		if err := json.Unmarshal([]byte(resp.Body), &response); err != nil {
			break
		}

		cont = false
		if len(response.Facets.Hits) > 0 {
			cont = true
			// loop through the hits and append the snippets to the results
			for _, hit := range response.Facets.Hits {
				emails.InsertMany(re.FindAllString(hit.Content.Snippet, -1)...)
			}
		}
	}

	return g.store(e, emails.Slice(), g.source)
}

func (g *grepApp) store(e *et.Event, emails []string, src *et.Source) []*dbt.Entity {
	return support.StoreEmailsWithSource(e.Session, emails, g.source, g.name, g.name+"-Handler")
}

func (g *grepApp) process(e *et.Event, assets []*dbt.Entity, src *et.Source) {
	support.ProcessEmailsWithSource(e, assets, g.source)
}
