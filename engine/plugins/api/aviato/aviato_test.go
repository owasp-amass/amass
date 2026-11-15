// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// api serves Aviato's API to the key "good" and refuses every other key,
// keeping the requests it was sent.
type api struct {
	mu       sync.Mutex
	requests []string
	pages    map[string][]string
}

func (a *api) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	key := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")

	a.mu.Lock()
	a.requests = append(a.requests, key+" "+r.Method+" "+r.URL.Path+" "+r.URL.Query().Get("page"))
	a.mu.Unlock()

	if key != "good" {
		http.Error(w, `{"error":"unauthorized"}`, http.StatusUnauthorized)
		return
	}
	if r.URL.Path == "/company/search" {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"value":"Example"`) {
			_, _ = fmt.Fprint(w, `{"items":[]}`)
			return
		}

		_, _ = fmt.Fprint(w, `{"items":[{"id":"co-1","name":"Example"}]}`)
		return
	}

	pages := a.pages[r.URL.Path]
	var page int
	_, _ = fmt.Sscan(r.URL.Query().Get("page"), &page)
	if page >= len(pages) {
		_, _ = fmt.Fprint(w, `{"employees":[],"pages":0}`)
		return
	}

	_, _ = fmt.Fprint(w, pages[page])
}

func (a *api) sent() []string {
	a.mu.Lock()
	defer a.mu.Unlock()

	return slices.Clone(a.requests)
}

func newAviato(t *testing.T, a *api) (*aviato, *plugintest.Session, *plugintest.Dispatcher) {
	t.Helper()

	srv := httptest.NewServer(a)
	t.Cleanup(srv.Close)

	p := NewAviato().(*aviato)
	p.api = srv.URL
	p.rlimit = rate.NewLimiter(rate.Inf, 1)
	p.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	p.employees = &employees{name: p.name + "-Employees-Handler", plugin: p}
	p.companySearch = &companySearch{name: p.name + "-Company-Search-Handler", plugin: p}

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	return p, sess, &plugintest.Dispatcher{}
}

func employeesPage(pages int, names ...string) string {
	var list []map[string]any
	for _, n := range names {
		list = append(list, map[string]any{"person": map[string]any{"fullName": n}})
	}

	b, _ := json.Marshal(map[string]any{"employees": list, "pages": pages})
	return string(b)
}

// A refused key does not skip a page: the next key is asked for the same
// page, and every page is read.
func TestEmployeesTriesTheNextKeyForTheSamePage(t *testing.T) {
	a := &api{pages: map[string][]string{"/company/co-1/employees": {
		employeesPage(2, "Ada Lovelace"),
		employeesPage(2, "Grace Hopper"),
	}}}
	p, sess, disp := newAviato(t, a)

	org := sess.Asset(t, &oamorg.Organization{ID: "example", Name: "Example"})
	ident := sess.Asset(t, &oamgen.Identifier{UniqueID: AviatoCompanyID + ":co-1", ID: "co-1", Type: AviatoCompanyID})
	sess.Edge(t, org, &oamgen.SimpleRelation{Name: "id"}, ident)
	e := &et.Event{Entity: ident, Session: sess, Dispatcher: disp}

	orgent, people := p.employees.query(e, ident, []string{"bad", "good"})
	if orgent == nil || len(people) != 2 {
		t.Fatalf("got %d people for %v, want 2; requests %v", len(people), orgent, a.sent())
	}

	var good []string
	for _, r := range a.sent() {
		if strings.HasPrefix(r, "good ") {
			good = append(good, r)
		}
	}
	if !slices.Equal(good, []string{"good GET /company/co-1/employees 0", "good GET /company/co-1/employees 1"}) {
		t.Errorf("the good key was sent %v", good)
	}
}

// The company search finds the organization's Aviato ID by its brand name
// and links it to the organization.
func TestCompanySearchLinksTheID(t *testing.T) {
	a := &api{}
	p, sess, disp := newAviato(t, a)

	org := sess.Asset(t, &oamorg.Organization{ID: "example", Name: "Example, Inc."})
	e := &et.Event{Entity: org, Session: sess, Dispatcher: disp}

	ident := p.companySearch.query(e, org, []string{"bad", "good"})
	if ident == nil {
		t.Fatalf("no ID was found; requests %v", a.sent())
	}
	if id := ident.Asset.(*oamgen.Identifier); id.ID != "co-1" || id.Type != AviatoCompanyID {
		t.Errorf("got %+v", id)
	}

	edges, err := sess.DB().OutgoingEdges(sess.Ctx(), org, ident.CreatedAt.AddDate(0, 0, -1), "id")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != ident.ID {
		t.Errorf("the organization's id edges are %v (%v)", edges, err)
	}

	// an organization the API does not know gets no ID
	other := sess.Asset(t, &oamorg.Organization{ID: "other", Name: "Unknown Things"})
	if got := p.companySearch.query(&et.Event{Entity: other, Session: sess, Dispatcher: disp}, other,
		[]string{"good"}); got != nil {
		t.Errorf("an unknown organization got %v", got.Asset)
	}
}
