// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package archive

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"sync/atomic"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
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

// The archived URLs' in-scope names are stored once each, in lowercase,
// and the name is not asked about again within the TTL.
func TestWaybackNames(t *testing.T) {
	w, _, disp, e, hits := newWayback(t, http.StatusOK, `[["original"],
		["https://WWW.Example.com/index.html"],["http://www.example.com/a"],
		["https://dev.example.com:8443/x"],["https://cdn.other.net/example.com"],["bad","row"]]`)

	for range 2 {
		if err := w.check(e); err != nil {
			t.Fatal(err)
		}
	}

	got := disp.Names()
	slices.Sort(got)
	if !slices.Equal(got, []string{"dev.example.com", "www.example.com"}) {
		t.Errorf("dispatched %v", got)
	}
	if hits.Load() != 1 {
		t.Errorf("the archive was asked %d times, want once within the TTL", hits.Load())
	}
}

// A rate limited or failed answer is not read for names.
func TestWaybackRefusal(t *testing.T) {
	w, _, disp, e, _ := newWayback(t, http.StatusTooManyRequests, `[["https://www.example.com/"]]`)

	if err := w.check(e); err != nil {
		t.Fatal(err)
	}
	if got := disp.Names(); len(got) != 0 {
		t.Errorf("a refused answer gave %v", got)
	}
}
