// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package wikidata

import (
	"context"
	"encoding/json"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// The forward direction of the Wikidata plugin: for an in-scope Organization it
// resolves the org to a Wikidata entity and records that entity's official
// websites (P856) as Organization --website--> URL --domain--> FQDN. Those
// domains are candidate horizontal apexes the related-domains lens surfaces for
// review; this handler never changes scope (ai-design-principles.md, principles
// 10 & 13). Uses the Wikidata REST API (wbsearchentities + EntityData), unlike
// the reverse domain->org handler which uses SPARQL.

type websiteHandler struct {
	name   string
	plugin *wikidata
}

func (h *websiteHandler) check(e *et.Event) error {
	o, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return nil
	}
	// Horizontal discovery only runs when scope expansion is allowed.
	if !e.Session.Config().Widens() || strings.TrimSpace(o.Name) == "" {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.URL), h.plugin.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, h.plugin.source, since) {
		return nil
	}

	sites := h.plugin.officialWebsites(e, o.Name)
	support.MarkAssetMonitored(e.Session, e.Entity, h.plugin.source)
	if len(sites) > 0 {
		h.plugin.storeWebsites(e, e.Entity, sites)
	}
	return nil
}

// officialWebsites resolves an organization name to a Wikidata entity and
// returns its official-website (P856) URLs.
func (w *wikidata) officialWebsites(e *et.Event, name string) []string {
	_ = support.WaitLimit(e.Session.Ctx(), w.rlimit)
	e.Session.NetSem().Acquire()
	defer e.Session.NetSem().Release()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Minute)
	defer cancel()

	sresp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: "https://www.wikidata.org/w/api.php?action=wbsearchentities&format=json&language=en&type=item&search=" +
			url.QueryEscape(name),
	})
	if err != nil || sresp == nil {
		return nil
	}
	qid := parseWikidataQID(sresp.Body)
	if qid == "" {
		return nil
	}

	eresp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, &amasshttp.Request{
		URL: "https://www.wikidata.org/wiki/Special:EntityData/" + qid + ".json",
	})
	if err != nil || eresp == nil {
		return nil
	}
	return parseOfficialWebsites(eresp.Body, qid)
}

// parseWikidataQID returns the top wbsearchentities match's entity id.
func parseWikidataQID(body string) string {
	var r struct {
		Search []struct {
			ID string `json:"id"`
		} `json:"search"`
	}
	if json.Unmarshal([]byte(body), &r) != nil || len(r.Search) == 0 {
		return ""
	}
	return r.Search[0].ID
}

// parseOfficialWebsites returns the official-website (P856) URLs from a Wikidata
// EntityData JSON response for the given entity id.
func parseOfficialWebsites(body, qid string) []string {
	var data struct {
		Entities map[string]struct {
			Claims map[string][]struct {
				Mainsnak struct {
					Datavalue struct {
						Value json.RawMessage `json:"value"`
					} `json:"datavalue"`
				} `json:"mainsnak"`
			} `json:"claims"`
		} `json:"entities"`
	}
	if json.Unmarshal([]byte(body), &data) != nil {
		return nil
	}
	ent, ok := data.Entities[qid]
	if !ok {
		return nil
	}

	var out []string
	seen := make(map[string]bool)
	for _, claim := range ent.Claims["P856"] {
		var site string
		if json.Unmarshal(claim.Mainsnak.Datavalue.Value, &site) != nil {
			continue
		}
		site = strings.TrimSpace(site)
		if site == "" || seen[site] {
			continue
		}
		seen[site] = true
		out = append(out, site)
	}
	return out
}

// storeWebsites records the organization's official websites as
// Organization --website--> URL --domain--> FQDN, tagged Wikidata.
func (w *wikidata) storeWebsites(e *et.Event, orgent *dbt.Entity, sites []string) {
	for _, site := range sites {
		org.LinkWebsite(e.Session, orgent, site, urlHost(site), w.source)
	}
}

func urlHost(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return ""
	}
	return strings.ToLower(u.Hostname())
}
