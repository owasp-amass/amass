// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package archive collects from web archives — the Wayback Machine and the
// Common Crawl index — the URLs they captured for an in-scope domain. Every
// archived URL's in-scope host is stored as a name (subdomain discovery), and
// the URLs worth keeping — not images, stylesheets, fonts or media, at most
// max_urls_per_domain of them (internal/semantics/archive_urls.json) — are
// stored as URL assets with the date the archive first captured them. Nothing
// is fetched from the target: only the archives are asked. See the OSINT
// collectors program, Unit 12.
package archive

import (
	"context"
	"log/slog"
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
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/net/publicsuffix"
)

// PropArchiveFirstSeen is the property an archived URL carries: the date the
// archive first captured it (RFC 3339). The web lens reads it to tell an
// archived URL from one seen live.
const PropArchiveFirstSeen = "archive_first_seen"

// archiveRow is one capture an archive returned: the URL and its capture
// timestamp (YYYYMMDDhhmmss), which may be empty.
type archiveRow struct {
	raw       string
	timestamp string
}

// archivedURL is one URL kept from an archive, with its first capture date.
type archivedURL struct {
	url       *oamurl.URL
	firstSeen string
}

// queryRoot reports whether name is the one an archive is asked about for
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

// harvest reads an archive's captures: it stores the in-scope names their
// URLs contain and returns those entities, and returns the in-scope URLs
// worth keeping, each once with its earliest capture, capped per the rules.
func harvest(e *et.Event, src *et.Source, pname string, rows []archiveRow) ([]*dbt.Entity, []archivedURL) {
	subs := stringset.New()
	defer subs.Close()

	rules := semantics.ArchiveURLs()
	index := map[string]int{}
	var urls []archivedURL
	for _, row := range rows {
		if n := strings.ToLower(amassdns.AnySubdomainRegex().FindString(row.raw)); n != "" {
			// if the subdomain is not in scope, skip it
			if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: n}, 0); conf > 0 {
				subs.Insert(n)
			}
		}

		u := support.RawURLToOAM(row.raw)
		if u == nil || u.Host == "" || rules.IsStaticPath(u.Path) {
			continue
		}
		if _, conf := e.Session.Scope().IsAssetInScope(&oamdns.FQDN{Name: u.Host}, 0); conf == 0 {
			continue
		}

		ts := captureDate(row.timestamp)
		if i, ok := index[u.Raw]; ok {
			// keep the earliest capture of a URL seen more than once
			if ts != "" && (urls[i].firstSeen == "" || ts < urls[i].firstSeen) {
				urls[i].firstSeen = ts
			}
			continue
		}

		index[u.Raw] = len(urls)
		urls = append(urls, archivedURL{url: u, firstSeen: ts})
	}

	names := support.StoreFQDNsWithSource(e.Session, subs.Slice(), src, pname, pname+"-Handler")
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
func storeURLs(e *et.Event, src *et.Source, pname string, urls []archivedURL) {
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
			Source:     src.Name,
			Confidence: src.Confidence,
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
		slog.Group("plugin", "name", pname, "handler", pname+"-Handler"))
}

// logRefusal records why an archive gave no usable answer for a domain: the
// HTTP status, or the error when the request or the reply failed.
func logRefusal(e *et.Event, pname, domain string, resp *amasshttp.Response, err error) {
	attrs := []any{"domain", domain}
	if resp != nil {
		attrs = append(attrs, "status", resp.StatusCode)
	}
	if err != nil {
		attrs = append(attrs, "error", err.Error())
	}
	attrs = append(attrs, slog.Group("plugin", "name", pname, "handler", pname+"-Handler"))
	e.Session.Log().Info("archive did not answer", attrs...)
}

// logAnswer records what an archive's answer for a domain held: the captures
// read, the in-scope names found in them and the URLs kept, so an answer
// that keeps nothing is told apart from no answer at all.
func logAnswer(e *et.Event, pname, domain string, captures, names, urls int) {
	e.Session.Log().Info("archive answered", "domain", domain, "captures", captures, "names", names,
		"urls", urls, slog.Group("plugin", "name", pname, "handler", pname+"-Handler"))
}
