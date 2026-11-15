// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scrape

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// site serves the pages a test gives, by path, counting the requests; any
// other path is a 404.
func site(t *testing.T, pages map[string]func(w http.ResponseWriter)) (*httptest.Server, *atomic.Int32) {
	t.Helper()

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if page, ok := pages[r.URL.Path]; ok {
			page(w)
			return
		}

		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)

	return srv, &hits
}

func body(s string) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) { _, _ = fmt.Fprint(w, s) }
}

func status(code int) func(w http.ResponseWriter) {
	return func(w http.ResponseWriter) { http.Error(w, "slow down: a.example.com", code) }
}

func session(t *testing.T) (*plugintest.Session, *plugintest.Dispatcher) {
	t.Helper()

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.com")
	return sess, &plugintest.Dispatcher{}
}

var unlimited = rate.NewLimiter(rate.Inf, 1)

// Only the in-scope names are kept, and paging stops at the first page that
// adds no new name.
func TestScrapePagesStopsWhenNothingIsNew(t *testing.T) {
	sess, _ := session(t)
	srv, hits := site(t, map[string]func(http.ResponseWriter){
		"/1": body("www.example.com mail.example.com other.org"),
		"/2": body("dev.example.com www.example.com"),
		"/3": body("www.example.com dev.example.com"),
		"/4": body("late.example.com"),
	})

	got := scrapePages(&et.Event{Session: sess}, unlimited, 10, func(i int) string {
		return fmt.Sprintf("%s/%d", srv.URL, i)
	})
	slices.Sort(got)
	if strings.Join(got, ",") != "dev.example.com,mail.example.com,www.example.com" {
		t.Errorf("got %v", got)
	}
	if hits.Load() != 3 {
		t.Errorf("%d pages were requested, want 3: the third added nothing", hits.Load())
	}
}

// A site that rate limits or fails is not asked for more pages, and its
// error page is not read for names.
func TestScrapePagesStopsOnRefusal(t *testing.T) {
	for _, code := range []int{http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusForbidden} {
		sess, _ := session(t)
		srv, hits := site(t, map[string]func(http.ResponseWriter){
			"/1": body("www.example.com"),
			"/2": status(code),
			"/3": body("dev.example.com"),
		})

		got := scrapePages(&et.Event{Session: sess}, unlimited, 10, func(i int) string {
			return fmt.Sprintf("%s/%d", srv.URL, i)
		})
		if strings.Join(got, ",") != "www.example.com" || hits.Load() != 2 {
			t.Errorf("status %d: got %v after %d requests, want www.example.com after 2", code, got, hits.Load())
		}
	}
}

// The page limit is kept even when every page has new names.
func TestScrapePagesKeepsThePageLimit(t *testing.T) {
	sess, _ := session(t)
	pages := map[string]func(http.ResponseWriter){}
	for i := 1; i <= 10; i++ {
		pages[fmt.Sprintf("/%d", i)] = body(fmt.Sprintf("n%d.example.com", i))
	}

	srv, hits := site(t, pages)

	_ = scrapePages(&et.Event{Session: sess}, unlimited, 3, func(i int) string {
		return fmt.Sprintf("%s/%d", srv.URL, i)
	})
	if hits.Load() != 3 {
		t.Errorf("%d pages were requested, want 3", hits.Load())
	}
}

// A scraping plugin stores and dispatches the in-scope names it finds, and
// does not ask again for the same name within the TTL.
func TestScraperFindsNamesOncePerTTL(t *testing.T) {
	srv, hits := site(t, map[string]func(http.ResponseWriter){
		"/example.com": body("<a href='https://api.example.com/'>api.example.com</a> cdn.other.net"),
	})

	sess, disp := session(t)
	rd := NewRapidDNS().(*rapidDNS)
	rd.rlimit = unlimited
	rd.fmtstr = srv.URL + "/%s"

	name := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	e := &et.Event{Name: "example.com", Entity: name, Session: sess, Dispatcher: disp,
		Meta: &support.FQDNMeta{SLDInScope: true}}
	if err := rd.check(e); err != nil {
		t.Fatal(err)
	}
	if got := disp.Names(); !slices.Equal(got, []string{"api.example.com"}) {
		t.Errorf("dispatched %v, want api.example.com", got)
	}

	if err := rd.check(e); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 1 {
		t.Errorf("the site was asked %d times, want once within the TTL", hits.Load())
	}
}

// Names outside the scope's registered domains are not looked up at all.
func TestScraperSkipsNamesOutOfScope(t *testing.T) {
	srv, hits := site(t, nil)

	sess, disp := session(t)
	d := NewDuckDuckGo().(*duckDuckGo)
	d.rlimit = unlimited
	d.fmtstr = srv.URL + "/%s/%s"

	name := sess.Asset(t, &oamdns.FQDN{Name: "other.org"})
	if err := d.check(&et.Event{Name: "other.org", Entity: name, Session: sess, Dispatcher: disp,
		Meta: &support.FQDNMeta{SLDInScope: false}}); err != nil {
		t.Fatal(err)
	}
	if hits.Load() != 0 {
		t.Errorf("the site was asked %d times for a name out of scope", hits.Load())
	}
}

// IPverse adds an autonomous system's announced netblocks once within the
// TTL, and asks again later when the site refused.
func TestIPVerseNetblocks(t *testing.T) {
	refuse := atomic.Bool{}
	refuse.Store(true)
	srv, hits := site(t, map[string]func(http.ResponseWriter){
		"/64496": func(w http.ResponseWriter) {
			if refuse.Load() {
				status(http.StatusTooManyRequests)(w)
				return
			}

			body(`{"asn":64496,"subnets":{"ipv4":["192.0.2.0/24"],"ipv6":["2001:db8::/32"]}}`)(w)
		},
	})

	sess, _ := session(t)
	v := NewIPVerse().(*ipverse)
	v.rlimit = unlimited
	v.fmtstr = srv.URL + "/%d"
	as := sess.Asset(t, &oamnet.AutonomousSystem{Number: 64496})
	e := &et.Event{Name: "AS64496", Entity: as, Session: sess}

	if err := v.check(e); err != nil {
		t.Fatal(err)
	}
	if n, _ := sess.CIDRanger().ContainingNetworks(net.ParseIP("192.0.2.1")); len(n) != 0 {
		t.Error("a refused request added netblocks")
	}

	refuse.Store(false)
	for range 2 {
		if err := v.check(e); err != nil {
			t.Fatal(err)
		}
	}
	for _, ip := range []string{"192.0.2.1", "2001:db8::1"} {
		if n, _ := sess.CIDRanger().ContainingNetworks(net.ParseIP(ip)); len(n) != 1 {
			t.Errorf("%s is in %d netblocks, want 1", ip, len(n))
		}
	}
	if hits.Load() != 2 {
		t.Errorf("the site was asked %d times, want twice: once refused, then once within the TTL", hits.Load())
	}
}
