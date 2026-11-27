// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"context"
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
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
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
	bodies   map[string]string
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
		// the search is by the organization's name key
		if !strings.Contains(string(body), `"value":"example"`) {
			_, _ = fmt.Fprint(w, `{"items":[]}`)
			return
		}

		_, _ = fmt.Fprint(w, `{"items":[{"id":"co-1","name":"Example"}]}`)
		return
	}

	if body, ok := a.bodies[r.URL.Path]; ok {
		_, _ = fmt.Fprint(w, body)
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
	p.companyEnrich = &companyEnrich{name: p.name + "-Company-Enrich-Handler", plugin: p}
	p.companyRounds = &companyRounds{name: p.name + "-Company-Rounds-Handler", plugin: p}

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
	sess.Scope().Add(org.Asset)
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
	sess.Scope().Add(org.Asset)
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
	sess.Scope().Add(other.Asset)
	if got := p.companySearch.query(&et.Event{Entity: other, Session: sess, Dispatcher: disp}, other,
		[]string{"good"}); got != nil {
		t.Errorf("an unknown organization got %v", got.Asset)
	}
}

// linkedCompany stores an organization with the Aviato company ID co-1, as the
// company search links it, and configures the keys "bad" and "good".
func linkedCompany(t *testing.T, p *aviato, sess *plugintest.Session, disp *plugintest.Dispatcher) (*dbt.Entity, *dbt.Entity) {
	t.Helper()

	sess.APIKeys(p.name, "bad", "good")
	org := sess.Asset(t, &oamorg.Organization{ID: "example", Name: "Example"})
	sess.Scope().Add(org.Asset)
	ident := p.companySearch.store(&et.Event{Entity: org, Session: sess, Dispatcher: disp}, org, "co-1")
	if ident == nil {
		t.Fatal("the company ID was not linked")
	}
	return org, ident
}

// The enrichment fills in the organization behind a company ID, and within
// the TTL answers from the database.
func TestCompanyEnrichUpdatesTheOrganization(t *testing.T) {
	a := &api{bodies: map[string]string{"/company/enrich": `{"id":"co-1","name":"Example",` +
		`"legalName":"Example Holdings, Inc.","status":"Active","headcount":250,"isNonProfit":true}`}}
	p, sess, disp := newAviato(t, a)
	org, ident := linkedCompany(t, p, sess, disp)

	if err := p.companyEnrich.check(&et.Event{Entity: ident, Session: sess, Dispatcher: disp}); err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(disp.Names(), "Example:example") {
		t.Fatalf("the organization was not dispatched: %v; requests %v", disp.Names(), a.sent())
	}

	ctx := context.Background()
	stored, err := sess.DB().FindEntityById(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	o := stored.Asset.(*oamorg.Organization)
	if o.LegalName != "Example Holdings, Inc." || o.Headcount != 250 || !o.Active || !o.NonProfit {
		t.Errorf("the organization was not enriched: %+v", o)
	}

	var legal bool
	if edges, err := sess.DB().OutgoingEdges(ctx, org, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if ent, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
				if id, ok := ent.Asset.(*oamgen.Identifier); ok && id.Type == oamgen.LegalName {
					legal = id.ID == "Example Holdings, Inc."
				}
			}
		}
	}
	if !legal {
		t.Error("the legal name Identifier was not linked")
	}

	sent := len(a.sent())
	disp2 := &plugintest.Dispatcher{}
	if err := p.companyEnrich.check(&et.Event{Entity: ident, Session: sess, Dispatcher: disp2}); err != nil {
		t.Fatal(err)
	}
	if len(a.sent()) != sent {
		t.Errorf("the API was asked again within the TTL: %v", a.sent()[sent:])
	}
	if !slices.Contains(disp2.Names(), "Example:example") {
		t.Errorf("the organization was not dispatched within the TTL: %v", disp2.Names())
	}
}

// A funding round becomes a funds transfer from an account the investors
// hold to the organization's account, and the investors' IDs are dispatched.
func TestCompanyRoundsRecordsTheRoundAndItsInvestors(t *testing.T) {
	round := `{"fundingRounds":[{"id":1,"announcedOn":"2024-03-01","moneyRaised":5000000,` +
		`"name":"Example Series A","stage":"series_a",` +
		`"personInvestorList":[{"id":"p-1","fullName":"Ada Lovelace"}],` +
		`"companyInvestorList":[{"id":"co-9","name":"Analytical Ventures"}]}],"pages":1}`
	a := &api{pages: map[string][]string{"/company/co-1/funding-rounds": {round}}}
	p, sess, disp := newAviato(t, a)
	org, ident := linkedCompany(t, p, sess, disp)

	if err := p.companyRounds.check(&et.Event{Entity: ident, Session: sess, Dispatcher: disp}); err != nil {
		t.Fatal(err)
	}

	var fund *dbt.Entity
	for _, ev := range disp.Events() {
		if _, ok := ev.Entity.Asset.(*oamfin.FundsTransfer); ok {
			fund = ev.Entity
		}
	}
	if fund == nil {
		t.Fatalf("no funds transfer was dispatched: %v; requests %v", disp.Names(), a.sent())
	}
	if f := fund.Asset.(*oamfin.FundsTransfer); f.Amount != 5000000 || f.Currency != "USD" {
		t.Errorf("funds transfer = %+v", f)
	}
	for _, want := range []string{AviatoPersonID + ":p-1", AviatoCompanyID + ":co-9"} {
		if !slices.Contains(disp.Names(), want) {
			t.Errorf("the investor %s was not dispatched: %v", want, disp.Names())
		}
	}

	// The recipient is the organization's account.
	ctx := context.Background()
	recv, err := sess.DB().OutgoingEdges(ctx, fund, time.Time{}, "recipient")
	if err != nil || len(recv) != 1 {
		t.Fatalf("recipient edges = %v, %v", recv, err)
	}
	accts, err := sess.DB().OutgoingEdges(ctx, org, time.Time{}, "account")
	if err != nil || len(accts) != 1 || accts[0].ToEntity.ID != recv[0].ToEntity.ID {
		t.Errorf("the recipient is not the organization's account: %v, %v", accts, err)
	}

	// The sender is an account both investors hold.
	send, err := sess.DB().OutgoingEdges(ctx, fund, time.Time{}, "sender")
	if err != nil || len(send) != 1 {
		t.Fatalf("sender edges = %v, %v", send, err)
	}
	holders, err := sess.DB().IncomingEdges(ctx, send[0].ToEntity, time.Time{}, "account")
	if err != nil || len(holders) != 2 {
		t.Errorf("the seed account's holders = %v, %v", holders, err)
	}

	// One page was reported, so one page was read with the good key.
	var good []string
	for _, r := range a.sent() {
		if strings.HasPrefix(r, "good ") {
			good = append(good, r)
		}
	}
	if !slices.Equal(good, []string{"good GET /company/co-1/funding-rounds 0"}) {
		t.Errorf("the good key was sent %v", good)
	}
}
