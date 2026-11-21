// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package archive collects from web archives: the URLs the Wayback Machine
// captured for an in-scope domain. Every archived URL's in-scope host is
// stored as a name (subdomain discovery), and the URLs worth keeping — not
// images, stylesheets, fonts or media, at most max_urls_per_domain of them
// (internal/semantics/archive_urls.json) — are stored as URL assets with the
// date the archive first captured them. Nothing is fetched from the target:
// the archive is the only thing asked. See the OSINT collectors program,
// Unit 12.
package archive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassdns "github.com/owasp-amass/amass/v5/internal/net/dns"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/net/publicsuffix"
	"golang.org/x/time/rate"
)

// PropArchiveFirstSeen is the property an archived URL carries: the date the
// archive first captured it (RFC 3339). The web lens reads it to tell an
// archived URL from one seen live.
const PropArchiveFirstSeen = "archive_first_seen"

type wayback struct {
	name   string
	URL    string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewWayback() et.Plugin {
	limit := rate.Every(10 * time.Second)

	return &wayback{
		name: "Wayback",
		// One row per distinct URL (collapse=urlkey) with the timestamp of its
		// first capture.
		URL:    "https://web.archive.org/cdx/search/cdx?matchType=domain&fl=original,timestamp&output=json&collapse=urlkey&url=",
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
		Plugin:       w,
		Name:         w.name + "-Handler",
		Position:     40,
		MaxInstances: 1,
		Transforms:   []string{string(oam.FQDN), string(oam.URL)},
		EventType:    oam.FQDN,
		Callback:     w.check,
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

	if !support.HasSLDInScope(e) || !queryRoot(e.Session, fqdn.Name) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.FQDN), string(oam.FQDN), w.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, w.source, since) {
		return nil
	}

	names, urls := w.query(e, fqdn.Name)
	support.MarkAssetMonitored(e.Session, e.Entity, w.source)

	if len(names) > 0 {
		support.ProcessFQDNsWithSource(e, names, w.source)
	}
	if len(urls) > 0 {
		w.storeURLs(e, urls)
	}
	return nil
}

// queryRoot reports whether name is the one the archive is asked about for
// its domain: the registered domain, or, when only a subdomain is in scope,
// the highest in-scope name. A domain-wide query covers every name below it,
// so asking again for each subdomain would only repeat it.
func queryRoot(sess et.Session, name string) bool {
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	reg, err := publicsuffix.EffectiveTLDPlusOne(name)
	if err != nil {
		return false
	}
	if reg == name {
		return true
	}

	_, parent, ok := strings.Cut(name, ".")
	if !ok {
		return false
	}

	_, conf := sess.Scope().IsAssetInScope(&oamdns.FQDN{Name: parent}, 0)
	return conf == 0
}

// archivedURL is one URL the archive captured, with its first capture date.
type archivedURL struct {
	url       *oamurl.URL
	firstSeen string
}

// query asks the archive for the domain and returns the in-scope names its
// URLs contain, already stored, and the in-scope URLs worth keeping.
func (w *wayback) query(e *et.Event, name string) ([]*dbt.Entity, []archivedURL) {
	_ = support.WaitLimit(e.Session.Ctx(), w.rlimit)
	e.Session.NetSem().Acquire()

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 60*time.Second)
	defer cancel()

	end := fmt.Sprintf("*.%s/*", name)
	resp, err := amasshttp.RequestWebPage(ctx,
		e.Session.Clients().General, &amasshttp.Request{URL: w.URL + end})
	e.Session.NetSem().Release()
	// a refusal or rate limit is not read as an answer
	if err != nil || resp == nil || resp.StatusCode != http.StatusOK {
		return nil, nil
	}

	var rows [][]string
	if err := json.Unmarshal([]byte(resp.Body), &rows); err != nil {
		return nil, nil
	}

	subs := stringset.New()
	defer subs.Close()

	rules := semantics.ArchiveURLs()
	seen := map[string]bool{}
	var urls []archivedURL
	for _, row := range rows {
		if len(row) < 1 || len(row) > 2 {
			continue
		}
		raw := row[0]

		if n := strings.ToLower(amassdns.AnySubdomainRegex().FindString(raw)); n != "" {
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				subs.Insert(n)
			}
		}

		u := support.RawURLToOAM(raw)
		if u == nil || u.Host == "" || seen[u.Raw] || rules.IsStaticPath(u.Path) {
			continue
		}
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: u.Host}, 0); conf == 0 {
			continue
		}

		seen[u.Raw] = true
		var ts string
		if len(row) == 2 {
			ts = captureDate(row[1])
		}
		urls = append(urls, archivedURL{url: u, firstSeen: ts})
	}

	names := support.StoreFQDNsWithSource(e.Session, subs.Slice(), w.source, w.name, w.name+"-Handler")
	return names, keepURLs(urls, rules.MaxURLsPerDomain)
}

// keepURLs caps the archived URLs at limit, preferring URLs with a query
// string, then deeper paths, so parameters and application endpoints
// survive the cap; ties are broken by the URL for a stable choice.
func keepURLs(urls []archivedURL, limit int) []archivedURL {
	if len(urls) <= limit {
		return urls
	}

	rank := func(u *oamurl.URL) int {
		r := strings.Count(strings.Trim(u.Path, "/"), "/")
		if strings.Contains(u.Raw, "?") {
			r += 1000
		}
		return r
	}
	sort.SliceStable(urls, func(i, j int) bool {
		ri, rj := rank(urls[i].url), rank(urls[j].url)
		if ri != rj {
			return ri > rj
		}
		return urls[i].url.Raw < urls[j].url.Raw
	})

	return urls[:limit]
}

// captureDate turns a CDX timestamp (YYYYMMDDhhmmss) into RFC 3339, or ""
// when it is not one.
func captureDate(ts string) string {
	t, err := time.Parse("20060102150405", ts)
	if err != nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339)
}

// storeURLs stores the archived URLs with the source and their first capture
// date, and dispatches each so the URL pipeline links it to its host. The
// URL pipeline only records the URL's name or address; it fetches nothing.
func (w *wayback) storeURLs(e *et.Event, urls []archivedURL) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Duration(len(urls)+10)*time.Second)
	defer cancel()

	for _, au := range urls {
		if ctx.Err() != nil {
			return
		}

		ent, err := e.Session.DB().CreateAsset(ctx, au.url)
		if err != nil || ent == nil {
			continue
		}

		_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &oamgen.SourceProperty{
			Source:     w.source.Name,
			Confidence: w.source.Confidence,
		})
		if au.firstSeen != "" {
			_, _ = e.Session.DB().CreateEntityProperty(ctx, ent, &oamgen.SimpleProperty{
				PropertyName:  PropArchiveFirstSeen,
				PropertyValue: au.firstSeen,
			})
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{Name: "URL: " + au.url.Raw, Entity: ent, Session: e.Session})
	}

	e.Session.Log().Info("archived URLs stored", "count", len(urls),
		slog.Group("plugin", "name", w.name, "handler", w.name+"-Handler"))
}
