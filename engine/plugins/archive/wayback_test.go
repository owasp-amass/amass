// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamurl "github.com/owasp-amass/open-asset-model/url"
	"golang.org/x/time/rate"
)

func newWayback(t *testing.T, code int, page string) (*wayback, *plugintest.Session, *plugintest.Dispatcher,
	*et.Event, *atomic.Int32) {
	t.Helper()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(code)
		_, _ = fmt.Fprint(w, page)
	}))
	t.Cleanup(srv.Close)

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.com")
	disp := &plugintest.Dispatcher{}

	w := NewWayback().(*wayback)
	w.rlimit = rate.NewLimiter(rate.Inf, 1)
	w.URL = srv.URL + "/cdx?url="

	name := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	return w, sess, disp, &et.Event{Name: "example.com", Entity: name, Session: sess, Dispatcher: disp,
		Meta: &support.FQDNMeta{SLDInScope: true}}, &hits
}

// dispatched splits the dispatched events into the names and the URLs.
func dispatched(d *plugintest.Dispatcher) (names, urls []string) {
	for _, e := range d.Events() {
		switch a := e.Entity.Asset.(type) {
		case *oamdns.FQDN:
			names = append(names, a.Name)
		case *oamurl.URL:
			urls = append(urls, a.Raw)
		}
	}

	slices.Sort(names)
	slices.Sort(urls)
	return names, urls
}

const archivePage = `[["original","timestamp"],
	["https://WWW.Example.com/index.html","20190304050607"],
	["http://www.example.com/login.php?next=/admin","20200101000000"],
	["https://www.example.com/img/logo.png","20200101000000"],
	["https://dev.example.com:8443/x","20210615120000"],
	["https://cdn.other.net/example.com","20200101000000"],
	["bad","row","extra"]]`

// The archived URLs' in-scope names are stored once each, in lowercase, and
// the domain is not asked about again within the TTL.
func TestWaybackNames(t *testing.T) {
	w, _, disp, e, hits := newWayback(t, http.StatusOK, archivePage)

	for range 2 {
		if err := w.check(e); err != nil {
			t.Fatal(err)
		}
	}

	names, _ := dispatched(disp)
	if !slices.Equal(names, []string{"dev.example.com", "www.example.com"}) {
		t.Errorf("dispatched names %v", names)
	}
	if hits.Load() != 1 {
		t.Errorf("the archive was asked %d times, want once within the TTL", hits.Load())
	}
}

// The in-scope URLs are kept, except static files, with the date the archive
// first captured them; an out-of-scope host's URL is not kept.
func TestWaybackURLs(t *testing.T) {
	w, sess, disp, e, _ := newWayback(t, http.StatusOK, archivePage)
	if err := w.check(e); err != nil {
		t.Fatal(err)
	}

	_, urls := dispatched(disp)
	want := []string{
		"http://www.example.com/login.php?next=/admin",
		"https://dev.example.com:8443/x",
		"https://www.example.com/index.html",
	}
	if !slices.Equal(urls, want) {
		t.Fatalf("kept URLs %v, want %v", urls, want)
	}

	ctx := context.Background()
	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.URL, time.Time{}, 0,
		dbt.ContentFilters{"url": "https://dev.example.com:8443/x"})
	if err != nil || len(ents) != 1 {
		t.Fatalf("stored URL lookup = %v, %v", ents, err)
	}
	tags, err := sess.DB().FindEntityTags(ctx, ents[0], time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var first, source string
	for _, tag := range tags {
		switch p := tag.Property.(type) {
		case *oamgen.SimpleProperty:
			if p.PropertyName == PropArchiveFirstSeen {
				first = p.PropertyValue
			}
		case *oamgen.SourceProperty:
			source = p.Source
		}
	}
	if first != "2021-06-15T12:00:00Z" || source != "Wayback" {
		t.Errorf("archive_first_seen = %q, source = %q", first, source)
	}
}

// A subdomain does not ask the archive again: the registered domain's
// domain-wide query already covers it.
func TestWaybackAsksOncePerDomain(t *testing.T) {
	w, sess, _, _, hits := newWayback(t, http.StatusOK, archivePage)

	sub := sess.Asset(t, &oamdns.FQDN{Name: "dev.example.com"})
	e := &et.Event{Name: "dev.example.com", Entity: sub, Session: sess, Dispatcher: &plugintest.Dispatcher{},
		Meta: &support.FQDNMeta{SLDInScope: true}}
	if err := w.check(e); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Errorf("a subdomain asked the archive %d times", hits.Load())
	}
}

// A rate limited or failed answer is not read for names or URLs.
func TestWaybackRefusal(t *testing.T) {
	w, _, disp, e, _ := newWayback(t, http.StatusTooManyRequests, `[["https://www.example.com/","20200101000000"]]`)

	if err := w.check(e); err != nil {
		t.Fatal(err)
	}
	if got := disp.Events(); len(got) != 0 {
		t.Errorf("a refused answer dispatched %d events", len(got))
	}
}

// Over the cap, URLs with a query string win, then deeper paths.
func TestKeepURLsPrefersParametersAndDepth(t *testing.T) {
	mk := func(raw string) archivedURL { return archivedURL{url: support.RawURLToOAM(raw)} }
	urls := []archivedURL{
		mk("https://www.example.com/"),
		mk("https://www.example.com/a/b/c"),
		mk("https://www.example.com/search?q=x"),
		mk("https://www.example.com/a"),
	}

	got := keepURLs(urls, 2)
	if len(got) != 2 || got[0].url.Raw != "https://www.example.com/search?q=x" ||
		got[1].url.Raw != "https://www.example.com/a/b/c" {
		t.Errorf("kept %v", []string{got[0].url.Raw, got[1].url.Raw})
	}
	if got := keepURLs(urls[:1], 2); len(got) != 1 {
		t.Errorf("under the cap, all URLs are kept: %d", len(got))
	}
}

// A page that holds more captures ends with an empty row and the resume key;
// the key is not read as a capture.
func TestWaybackRowsResumeKey(t *testing.T) {
	raw := [][]string{
		{"original", "timestamp"},
		{"https://www.example.com/a", "20200101000000"},
		{"https://www.example.com/b", "20200102000000"},
		{},
		{"com,example)/b 20200102000000"},
	}

	rows, next := waybackRows(raw)
	if len(rows) != 3 || rows[2].raw != "https://www.example.com/b" {
		t.Errorf("rows = %v, want the header and two captures", rows)
	}
	if next != "com,example)/b 20200102000000" {
		t.Errorf("resume key = %q", next)
	}

	if _, next := waybackRows(raw[:3]); next != "" {
		t.Errorf("the last page has no resume key, got %q", next)
	}
}
