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

		if support.MalformedURL(row.raw) {
			// a link cut from broken markup, captured as it was
			continue
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

// keepURLs caps the archived URLs at limit, preferring documents (PDF and
// Office files, which the documents collector reads), then URLs with a query
// string, then deeper paths, so documents, parameters and application
// endpoints survive the cap; ties are broken by the URL for a stable choice.
func keepURLs(urls []archivedURL, limit int) []archivedURL {
	if len(urls) <= limit {
		return urls
	}

	docs := semantics.Documents()
	rank := func(u *oamurl.URL) int {
		r := strings.Count(strings.Trim(u.Path, "/"), "/")
		if strings.Contains(u.Raw, "?") {
			r += 1000
		}
		if _, ok := docs.DocumentFor(u.Path); ok {
			r += 2000
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

		support.AddSource(ctx, e.Session, ent, src)
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

// archiveBackoff are the waits before each retry of an archive request that
// failed or that the server refused for load. The Wayback Machine and the
// Common Crawl index are keyless and often overloaded (502/503/504, 429), and
// a refusal is usually over within a minute or two.
var archiveBackoff = []time.Duration{20 * time.Second, time.Minute}

// overloaded reports whether a status is the server refusing for load, which
// is worth asking again, as opposed to an answer.
func overloaded(status int) bool {
	switch status {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// request GETs u, paced by lim, retrying after each wait in backoff while
// the request fails or the server refuses for load, until ctx (the reader's
// budget for the domain) ends. It returns the last response, so a refusal
// that outlasts the retries is still logged as one. Each request counts as a
// completed work item of the session, so a long reading shows progress.
func request(ctx context.Context, e *et.Event, lim *rate.Limiter, backoff []time.Duration, timeout time.Duration,
	u string) (*amasshttp.Response, error) {
	for attempt := 0; ; attempt++ {
		if err := support.WaitLimit(ctx, lim); err != nil {
			return nil, err
		}
		e.Session.Stats().AddBackground(1)
		e.Session.NetSem().Acquire()
		rctx, cancel := context.WithTimeout(ctx, timeout)
		resp, err := amasshttp.RequestWebPage(rctx, bulkClient(e), &amasshttp.Request{URL: u})
		cancel()
		e.Session.NetSem().Release()
		e.Session.Stats().DoneBackground(1)

		if (err == nil && resp != nil && !overloaded(resp.StatusCode)) || attempt >= len(backoff) {
			return resp, err
		}

		select {
		case <-ctx.Done():
			return resp, err
		case <-time.After(backoff[attempt]):
		}
	}
}

// bulkClient is the session's client for slow bulk queries: an archive's
// index for a whole domain can take minutes to start answering, longer than
// the General client waits.
func bulkClient(e *et.Event) *http.Client {
	if c := e.Session.Clients(); c.Bulk != nil {
		return c.Bulk
	}
	return e.Session.Clients().General
}
