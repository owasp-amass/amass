// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"fmt"
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
	"golang.org/x/time/rate"
)

const ccIndexPage = `{"url":"https://WWW.Example.com/index.html","timestamp":"20250102030405"}
{"url":"https://www.example.com/index.html","timestamp":"20240101000000"}
{"url":"https://api.example.com/v1/users?page=2","timestamp":"20250301000000"}
{"url":"https://www.example.com/static/site.css","timestamp":"20250102030405"}
{"url":"https://other.net/example.com","timestamp":"20250102030405"}
not json
`

type ccServer struct {
	listHits, indexHits atomic.Int32
	indexStatus         int
	query               atomic.Value
}

func newCommonCrawl(t *testing.T, indexStatus int) (*commonCrawl, *plugintest.Session, *plugintest.Dispatcher,
	*et.Event, *ccServer) {
	t.Helper()

	s := &ccServer{indexStatus: indexStatus}
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/collinfo.json":
			s.listHits.Add(1)
			_, _ = fmt.Fprintf(w, `[{"id":"CC-MAIN-2026-44","cdx-api":"%[1]s/CC-MAIN-2026-44-index"},
				{"id":"CC-MAIN-2026-40","cdx-api":"%[1]s/CC-MAIN-2026-40-index"}]`, srv.URL)
		case r.URL.Path == "/CC-MAIN-2026-44-index":
			s.indexHits.Add(1)
			s.query.Store(r.URL.RawQuery)
			w.WriteHeader(s.indexStatus)
			if s.indexStatus == http.StatusOK {
				_, _ = fmt.Fprint(w, ccIndexPage)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Scope().AddDomain("example.com")
	disp := &plugintest.Dispatcher{}

	c := NewCommonCrawl().(*commonCrawl)
	c.rlimit = rate.NewLimiter(rate.Inf, 1)
	c.backoff = nil
	c.IndexURL = srv.URL + "/collinfo.json"

	name := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	return c, sess, disp, &et.Event{Name: "example.com", Entity: name, Session: sess, Dispatcher: disp,
		Meta: &support.FQDNMeta{SLDInScope: true}}, s
}

// The newest crawl's index is asked about the whole domain; its in-scope names
// and non-static URLs are kept, each URL once with its earliest capture.
func TestCommonCrawlNamesAndURLs(t *testing.T) {
	c, _, disp, e, s := newCommonCrawl(t, http.StatusOK)
	if err := c.check(e); err != nil {
		t.Fatal(err)
	}

	q, _ := s.query.Load().(string)
	if !strings.Contains(q, "url=example.com") || !strings.Contains(q, "matchType=domain") ||
		!strings.Contains(q, "output=json") {
		t.Errorf("index query = %q", q)
	}

	names, urls := dispatched(disp)
	if !slices.Equal(names, []string{"api.example.com", "www.example.com"}) {
		t.Errorf("names = %v", names)
	}
	want := []string{"https://api.example.com/v1/users?page=2", "https://www.example.com/index.html"}
	if !slices.Equal(urls, want) {
		t.Errorf("urls = %v, want %v", urls, want)
	}
}

// The crawl list is read once and reused; the domain is not asked about again
// within the TTL.
func TestCommonCrawlCachesTheCrawlList(t *testing.T) {
	c, sess, _, e, s := newCommonCrawl(t, http.StatusOK)
	for range 2 {
		if err := c.check(e); err != nil {
			t.Fatal(err)
		}
	}

	sess.Scope().AddDomain("example.org")
	other := sess.Asset(t, &oamdns.FQDN{Name: "example.org"})
	if err := c.check(&et.Event{Name: "example.org", Entity: other, Session: sess,
		Dispatcher: &plugintest.Dispatcher{}, Meta: &support.FQDNMeta{SLDInScope: true}}); err != nil {
		t.Fatal(err)
	}

	if s.listHits.Load() != 1 || s.indexHits.Load() != 2 {
		t.Errorf("crawl list read %d times (want 1), index asked %d times (want 2)",
			s.listHits.Load(), s.indexHits.Load())
	}
}

// "No captures" is an answer: nothing is stored and the domain is not asked
// again within the TTL.
func TestCommonCrawlNoCaptures(t *testing.T) {
	c, _, disp, e, s := newCommonCrawl(t, http.StatusNotFound)
	for range 2 {
		if err := c.check(e); err != nil {
			t.Fatal(err)
		}
	}

	if len(disp.Events()) != 0 || s.indexHits.Load() != 1 {
		t.Errorf("no captures: %d events, index asked %d times", len(disp.Events()), s.indexHits.Load())
	}
}

// A refusal is not an answer: nothing is stored and the domain is asked again.
func TestCommonCrawlRefusal(t *testing.T) {
	c, _, disp, e, s := newCommonCrawl(t, http.StatusServiceUnavailable)
	for range 2 {
		if err := c.check(e); err != nil {
			t.Fatal(err)
		}
	}

	if len(disp.Events()) != 0 || s.indexHits.Load() != 2 {
		t.Errorf("refused: %d events, index asked %d times (want 2)", len(disp.Events()), s.indexHits.Load())
	}
}
