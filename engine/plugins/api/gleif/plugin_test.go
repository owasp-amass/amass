// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

const (
	acmeLEI   = "5493001KJTIIGC8Y1R12"
	parentLEI = "5493001KJTIIGC8Y1R99"
	childLEI  = "5493001KJTIIGC8Y1R55"
)

// newTestGLEIF returns a session with a fake web and the plugin with its
// handlers, with the register's rate limit lifted.
func newTestGLEIF(t *testing.T) (*plugintest.Session, *gleif) {
	t.Helper()

	old := gleifLimit
	gleifLimit = rate.NewLimiter(rate.Inf, 1)
	t.Cleanup(func() { gleifLimit = old })

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Web()

	g := NewGLEIF().(*gleif)
	g.fuzzy = &fuzzyCompletions{name: g.name + "-Fuzzy-Handler", plugin: g}
	g.related = &relatedOrgs{name: g.name + "-LEI-Handler", plugin: g}
	g.address = &addresses{name: g.name + "-Address-Handler", plugin: g}
	return sess, g
}

// servedRecord is the register's answer for an LEI: the match_test record
// with its type, LEI, status and a street line, as the API sends it.
func servedRecord(id, name, country, postal string) LEIRecord {
	r := leiRecord(name, country, country, postal)
	r.Type = "lei-records"
	r.ID = id
	r.Attributes.LEI = id
	r.Attributes.Entity.Status = "ACTIVE"
	r.Attributes.Registration.Status = "ISSUED"
	for _, addr := range []*LEIAddress{&r.Attributes.Entity.LegalAddress, &r.Attributes.Entity.HeadquartersAddress} {
		addr.AddressLines = []string{"1 Main Street"}
		addr.City = "Springfield"
	}
	return *r
}

func jsonBody(t *testing.T, v any) string {
	t.Helper()

	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func fuzzyBody(value, id string) string {
	return fmt.Sprintf(`{"data":[{"type":"fuzzycompletions","attributes":{"value":%q},`+
		`"relationships":{"lei-records":{"data":{"type":"lei-records","id":%q}}}}]}`, value, id)
}

// serveRecords answers the record lookups from recs, keyed by LEI.
func serveRecords(t *testing.T, sess *plugintest.Session, recs ...LEIRecord) {
	byID := map[string]LEIRecord{}
	for _, r := range recs {
		byID[r.ID] = r
	}

	sess.Web().Handle("GET api.gleif.org/api/v1/lei-records/{id}", func(w http.ResponseWriter, r *http.Request) {
		rec, ok := byID[r.PathValue("id")]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		_, _ = w.Write([]byte(jsonBody(t, SingleResponse{Data: rec})))
	})
}

// orgWithAddress stores an organization with a legal address in country.
func orgWithAddress(t *testing.T, sess *plugintest.Session, name, country, postal string) *dbt.Entity {
	t.Helper()

	orgent := sess.Asset(t, &oamorg.Organization{ID: name + ":test", Name: name})
	sess.Scope().Add(orgent.Asset)
	addr := sess.Asset(t, &contact.StreetAddress{Address: "1 Main Street Springfield " + postal + " " + country,
		BuildingNumber: "1", StreetName: "Main Street", City: "Springfield", Country: country, PostalCode: postal})
	sess.Edge(t, orgent, &oamgen.SimpleRelation{Name: "legal_address"}, addr)
	return orgent
}

// identifiers returns the Identifiers the entity links to over id edges,
// keyed by unique ID.
func identifiers(t *testing.T, sess *plugintest.Session, ent *dbt.Entity) map[string]*oamgen.Identifier {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, ent, time.Time{}, "id")
	if err != nil {
		return nil
	}

	out := map[string]*oamgen.Identifier{}
	for _, edge := range edges {
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			if id, ok := a.Asset.(*oamgen.Identifier); ok {
				out[id.UniqueID] = id
			}
		}
	}
	return out
}

func TestFuzzyCompletionsLinksTheLEIRecord(t *testing.T) {
	sess, g := newTestGLEIF(t)

	rec := servedRecord(acmeLEI, "ACME WIDGETS INC", "US", "62701")
	sess.Web().Reply("GET api.gleif.org/api/v1/fuzzycompletions", http.StatusOK, fuzzyBody("ACME WIDGETS INC", acmeLEI))
	serveRecords(t, sess, rec)

	orgent := orgWithAddress(t, sess, "Acme Widgets", "US", "62701")
	d := &plugintest.Dispatcher{}
	if err := g.fuzzy.check(&et.Event{Name: "acme", Entity: orgent, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	lei := oamgen.LEICode + ":" + acmeLEI
	if !slices.Contains(d.Names(), lei) {
		t.Fatalf("the LEI was not dispatched: %v", d.Names())
	}

	ids := identifiers(t, sess, orgent)
	if id := ids[lei]; id == nil || id.Status != "ISSUED" {
		t.Errorf("the LEI Identifier was not linked to the organization: %v", ids)
	}
	if ids[oamgen.LegalName+":ACME WIDGETS INC"] == nil {
		t.Errorf("the legal name was not recorded: %v", ids)
	}

	o := orgent.Asset.(*oamorg.Organization)
	if o.LegalName != "acme widgets inc" || o.Jurisdiction != "US" || !o.Active {
		t.Errorf("the organization was not updated from the record: %+v", o)
	}

	// Within the TTL the handler answers from the database, without asking
	// the register again.
	before := len(sess.Web().Requests())
	d2 := &plugintest.Dispatcher{}
	if err := g.fuzzy.check(&et.Event{Name: "acme", Entity: orgent, Session: sess, Dispatcher: d2}); err != nil {
		t.Fatal(err)
	}
	if after := len(sess.Web().Requests()); after != before {
		t.Errorf("the register was queried again within the TTL: %v", sess.Web().Requests()[before:])
	}
	if !slices.Contains(d2.Names(), lei) {
		t.Errorf("the stored LEI was not dispatched within the TTL: %v", d2.Names())
	}
}

func TestFuzzyCompletionsRejectsARecordInAnotherCountry(t *testing.T) {
	sess, g := newTestGLEIF(t)

	sess.Web().Reply("GET api.gleif.org/api/v1/fuzzycompletions", http.StatusOK, fuzzyBody("ACME WIDGETS INC", acmeLEI))
	serveRecords(t, sess, servedRecord(acmeLEI, "ACME WIDGETS INC", "US", "62701"))

	// The organization's own address places it in Germany.
	orgent := orgWithAddress(t, sess, "Acme Widgets", "DE", "10115")
	d := &plugintest.Dispatcher{}
	if err := g.fuzzy.check(&et.Event{Name: "acme", Entity: orgent, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	if len(d.Events()) != 0 {
		t.Errorf("a record in another country was accepted: %v", d.Names())
	}
	if ids := identifiers(t, sess, orgent); ids[oamgen.LEICode+":"+acmeLEI] != nil {
		t.Errorf("the LEI was linked: %v", ids)
	}
}

func TestFuzzyCompletionsUsesAKnownLEI(t *testing.T) {
	sess, g := newTestGLEIF(t)

	// With an LEI already on the organization, the record is read directly
	// and no name search is made.
	serveRecords(t, sess, servedRecord(acmeLEI, "ACME WIDGETS INC", "US", "62701"))

	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: "Acme"})
	sess.Scope().Add(orgent.Asset)
	ident := sess.Asset(t, &oamgen.Identifier{UniqueID: oamgen.LEICode + ":" + acmeLEI, ID: acmeLEI, Type: oamgen.LEICode})
	sess.Edge(t, orgent, &oamgen.SimpleRelation{Name: "id"}, ident)

	d := &plugintest.Dispatcher{}
	if err := g.fuzzy.check(&et.Event{Name: "acme", Entity: orgent, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	if reqs := sess.Web().Requests(); len(reqs) != 1 || reqs[0] != "GET api.gleif.org/api/v1/lei-records/"+acmeLEI {
		t.Errorf("requests = %v", reqs)
	}
	if !slices.Contains(d.Names(), oamgen.LEICode+":"+acmeLEI) {
		t.Errorf("the LEI was not dispatched: %v", d.Names())
	}
}

func TestRelatedOrgsAddsTheParentAndChildren(t *testing.T) {
	sess, g := newTestGLEIF(t)

	parent := servedRecord(parentLEI, "GAMMA HOLDINGS PLC", "GB", "EC1A1BB")
	child := servedRecord(childLEI, "BETA WERKE GMBH", "DE", "10115")
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records/"+acmeLEI+"/direct-parent", http.StatusOK,
		jsonBody(t, SingleResponse{Data: parent}))
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records/"+acmeLEI+"/direct-children", http.StatusOK,
		jsonBody(t, MultipleResponse{Data: []LEIRecord{child}}))

	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: "Acme Widgets"})
	sess.Scope().Add(orgent.Asset)
	ident, err := g.createLEIIdentifier(sess, orgent,
		&oamgen.Identifier{UniqueID: oamgen.LEICode + ":" + acmeLEI, ID: acmeLEI, Type: oamgen.LEICode}, 100)
	if err != nil {
		t.Fatal(err)
	}

	d := &plugintest.Dispatcher{}
	if err := g.related.check(&et.Event{Name: "lei", Entity: ident, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	// Organizations the plugin creates are named by their name key.
	names := map[string]bool{}
	for _, ev := range d.Events() {
		if o, ok := ev.Entity.Asset.(*oamorg.Organization); ok {
			names[semantics.OrgNameKey(o.Name)] = true
		}
	}
	if !names["acme widgets"] || !names[semantics.OrgNameKey("GAMMA HOLDINGS PLC")] ||
		!names[semantics.OrgNameKey("BETA WERKE GMBH")] {
		t.Fatalf("dispatched organizations = %v", names)
	}

	ctx := context.Background()
	if edges, err := sess.DB().IncomingEdges(ctx, orgent, time.Time{}, "subsidiary"); err != nil || len(edges) != 1 {
		t.Errorf("the parent's subsidiary edge = %v, %v", edges, err)
	}
	if edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "subsidiary"); err != nil || len(edges) != 1 {
		t.Errorf("the child's subsidiary edge = %v, %v", edges, err)
	}

	// Within the TTL the same family comes back from the database.
	before := len(sess.Web().Requests())
	d2 := &plugintest.Dispatcher{}
	if err := g.related.check(&et.Event{Name: "lei", Entity: ident, Session: sess, Dispatcher: d2}); err != nil {
		t.Fatal(err)
	}
	if len(sess.Web().Requests()) != before {
		t.Errorf("the register was queried again within the TTL")
	}
	if len(d2.Events()) != 3 {
		t.Errorf("organizations dispatched within the TTL = %v", d2.Names())
	}
}

func TestAddressesResolvesOrganizationsOnTheStreet(t *testing.T) {
	sess, g := newTestGLEIF(t)

	at := servedRecord(acmeLEI, "ACME WIDGETS INC", "US", "62701")
	elsewhere := servedRecord(childLEI, "OTHER CO", "US", "62701")
	elsewhere.Attributes.Entity.LegalAddress.AddressLines = []string{"500 Elm Street"}
	elsewhere.Attributes.Entity.HeadquartersAddress.AddressLines = []string{"500 Elm Street"}
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records", http.StatusOK,
		jsonBody(t, MultipleResponse{Data: []LEIRecord{at, elsewhere}}))

	loc := &contact.StreetAddress{Address: "1 Main Street Springfield IL 62701 US",
		BuildingNumber: "1", StreetName: "Main Street", City: "Springfield", Country: "US", PostalCode: "62701"}
	seed := sess.Asset(t, loc)
	sess.Scope().AddStreetAddress(loc) // a pivot seed is in scope
	d := &plugintest.Dispatcher{}
	if err := g.address.check(&et.Event{Name: "addr", Entity: seed, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	reqs := sess.Web().Requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %v", reqs)
	}
	for _, want := range []string{"country%5D=US", "fulltext%5D=Main+Street+Springfield"} {
		if !strings.Contains(reqs[0], want) {
			t.Errorf("the search %q is missing %q", reqs[0], want)
		}
	}

	evs := d.Events()
	if len(evs) != 1 {
		t.Fatalf("dispatched = %v", d.Names())
	}
	orgent := evs[0].Entity
	if o := orgent.Asset.(*oamorg.Organization); o.Name != semantics.OrgNameKey("ACME WIDGETS INC") {
		t.Errorf("resolved organization = %+v", o)
	}

	// The organization reaches the seed through a ContactRecord.
	ctx := context.Background()
	edges, err := sess.DB().IncomingEdges(ctx, seed, time.Time{}, "street_address")
	if err != nil || len(edges) != 1 {
		t.Fatalf("contact record edges to the seed = %v, %v", edges, err)
	}
	cr, err := sess.DB().FindEntityById(ctx, edges[0].FromEntity.ID)
	if err != nil {
		t.Fatal(err)
	}
	if out, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization"); err != nil || len(out) != 1 ||
		out[0].ToEntity.ID != orgent.ID {
		t.Errorf("the contact record does not name the organization: %v, %v", out, err)
	}

	// The seed is monitored: a second event does not search again.
	if err := g.address.check(&et.Event{Name: "addr", Entity: seed, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	if len(sess.Web().Requests()) != 1 {
		t.Errorf("the register was searched again within the TTL")
	}
}

func TestAddressesSkipsAnUnboundedSearch(t *testing.T) {
	sess, g := newTestGLEIF(t)

	// No country or postal code: the search would be too broad.
	seed := sess.Asset(t, &contact.StreetAddress{Address: "1 Main Street Springfield",
		BuildingNumber: "1", StreetName: "Main Street", City: "Springfield"})
	if err := g.address.check(&et.Event{Name: "addr", Entity: seed, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}
	if reqs := sess.Web().Requests(); len(reqs) != 0 {
		t.Errorf("requests = %v", reqs)
	}
}

// The register filters addresses only by country, so the search sends the
// street and city as full text, and a search missing any of the three is
// refused before it is sent.
func TestGLEIFSearchByAddressQuery(t *testing.T) {
	sess, _ := newTestGLEIF(t)
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records", http.StatusOK, jsonBody(t, MultipleResponse{}))

	ctx, client := context.Background(), sess.Clients().General
	if _, err := GLEIFSearchByAddress(ctx, client, "Microsoft Way", "Redmond", "US"); err != nil {
		t.Fatal(err)
	}

	reqs := sess.Web().Requests()
	if len(reqs) != 1 || strings.Contains(reqs[0], "city%5D") || strings.Contains(reqs[0], "postalCode%5D") ||
		!strings.Contains(reqs[0], "fulltext%5D=Microsoft+Way+Redmond") {
		t.Errorf("the search = %v; want the country filter and the street and city as full text", reqs)
	}

	for _, args := range [][3]string{{"", "Redmond", "US"}, {"Microsoft Way", "", "US"}, {"Microsoft Way", "Redmond", ""}} {
		if _, err := GLEIFSearchByAddress(ctx, client, args[0], args[1], args[2]); err == nil {
			t.Errorf("a search without all of %q was sent", args)
		}
	}
	if len(sess.Web().Requests()) != 1 {
		t.Error("an incomplete search reached the register")
	}
}

func TestGLEIFGetDirectChildrenRecordsFollowsPages(t *testing.T) {
	sess, _ := newTestGLEIF(t)

	page2 := "https://api.gleif.org/api/v1/lei-records/" + acmeLEI + "/direct-children?page=2"
	first := MultipleResponse{Data: []LEIRecord{servedRecord(childLEI, "ONE", "DE", "")}}
	first.Links.Next = page2
	first.Meta.Pagination.LastPage = 2
	second := MultipleResponse{Data: []LEIRecord{servedRecord(parentLEI, "TWO", "DE", "")}}
	sess.Web().Handle("GET api.gleif.org/api/v1/lei-records/{id}/direct-children", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("page") == "2" {
			_, _ = w.Write([]byte(jsonBody(t, second)))
			return
		}
		_, _ = w.Write([]byte(jsonBody(t, first)))
	})

	recs, err := GLEIFGetDirectChildrenRecords(context.Background(), sess.Clients().General, acmeLEI)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, r := range recs {
		names = append(names, r.Attributes.Entity.LegalName.Name)
	}
	if !slices.Equal(names, []string{"ONE", "TWO"}) {
		t.Errorf("children = %v", names)
	}
}

func TestGLEIFGetLEIRecordRejectsAnotherRecord(t *testing.T) {
	sess, _ := newTestGLEIF(t)
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records/"+acmeLEI, http.StatusOK,
		jsonBody(t, SingleResponse{Data: servedRecord(childLEI, "OTHER", "US", "")}))

	if rec, err := GLEIFGetLEIRecord(context.Background(), sess.Clients().General, acmeLEI); err == nil || rec != nil {
		t.Errorf("a record for another LEI was returned: %+v", rec)
	}
}

// A record the register does not answer for is an error, never a nil record
// without one, so callers that check only the error cannot use a nil record.
func TestGLEIFLookupsReportAFailedAnswer(t *testing.T) {
	sess, _ := newTestGLEIF(t)
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records/"+acmeLEI, http.StatusNotFound, "")
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records/"+acmeLEI+"/direct-parent", http.StatusNotFound, "")
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records/"+acmeLEI+"/direct-children", http.StatusInternalServerError, "")
	sess.Web().Reply("GET api.gleif.org/api/v1/lei-records", http.StatusServiceUnavailable, "")
	sess.Web().Reply("GET api.gleif.org/api/v1/fuzzycompletions", http.StatusOK, `{"data":[]}`)

	ctx, client := context.Background(), sess.Clients().General
	if rec, err := GLEIFGetLEIRecord(ctx, client, acmeLEI); err == nil || rec != nil {
		t.Errorf("a missing record gave %+v, %v", rec, err)
	}
	if rec, err := GLEIFGetDirectParentRecord(ctx, client, acmeLEI); err == nil || rec != nil {
		t.Errorf("a missing parent gave %+v, %v", rec, err)
	}
	if recs, err := GLEIFGetDirectChildrenRecords(ctx, client, acmeLEI); err == nil || recs != nil {
		t.Errorf("a failed children query gave %v, %v", recs, err)
	}
	if _, err := GLEIFSearchByAddress(ctx, client, "Main Street", "Utica", "US"); err == nil ||
		!strings.Contains(err.Error(), "status 503") {
		t.Errorf("a refused address search gave %v; want the status in the error", err)
	}
	if _, err := GLEIFSearchFuzzyCompletions(ctx, client, "Nobody Inc"); !errors.Is(err, errNoResults) {
		t.Errorf("a search without results gave %v; want errNoResults", err)
	}
}
