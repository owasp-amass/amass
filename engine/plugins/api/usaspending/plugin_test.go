// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usaspending

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// The contract group has two pages; the first page names the organization,
// a different recipient and an award repeated on the second page.
var contractPages = map[int]string{
	1: `{"results":[
	  {"Award ID":"C-1","Recipient Name":"ACME WIDGETS, INC.","Recipient UEI":"acmeuei12345","Award Amount":250000,
	   "Awarding Agency":"Department of Energy","Start Date":"2023-04-01","generated_internal_id":"CONT_AWD_C-1"},
	  {"Award ID":"C-9","Recipient Name":"Acme Widgets Foundation","Recipient UEI":"OTHERUEI0001","Award Amount":10,
	   "Awarding Agency":"Department of Energy","Start Date":"2023-04-01","generated_internal_id":"CONT_AWD_C-9"}
	],"page_metadata":{"hasNext":true}}`,
	2: `{"results":[
	  {"Award ID":"C-1","Recipient Name":"ACME WIDGETS, INC.","Recipient UEI":"acmeuei12345","Award Amount":250000,
	   "Awarding Agency":"Department of Energy","Start Date":"2023-04-01","generated_internal_id":"CONT_AWD_C-1"},
	  {"Award ID":"C-2","Recipient Name":"Acme Widgets","Recipient UEI":"ACMEUEI12345","Award Amount":5000,
	   "Awarding Agency":"Department of Defense","Start Date":"2022-01-15"}
	],"page_metadata":{"hasNext":false}}`,
}

func newTestUSASpending(t *testing.T) (*usaspending, *plugintest.Session) {
	t.Helper()

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Web().Handle("POST api.usaspending.gov/api/v2/search/spending_by_award/", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Filters struct {
				RecipientSearchText []string `json:"recipient_search_text"`
				AwardTypeCodes      []string `json:"award_type_codes"`
			} `json:"filters"`
			Fields []string `json:"fields"`
			Page   int      `json:"page"`
			Sort   string   `json:"sort"`
		}
		body, _ := io.ReadAll(r.Body)
		if err := json.Unmarshal(body, &req); err != nil || !slices.Equal(req.Filters.RecipientSearchText, []string{"acme widgets"}) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		// As the API does: loans have a loan value, not an award amount, and
		// the sort must be one of the fields asked for.
		loans := slices.Contains(req.Filters.AwardTypeCodes, "07")
		if loans == slices.Contains(req.Fields, "Award Amount") || !slices.Contains(req.Fields, req.Sort) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if loans {
			_, _ = io.WriteString(w, `{"results":[{"Award ID":"L-1","Recipient Name":"ACME WIDGETS INC",`+
				`"Loan Value":80000,"Awarding Agency":"Small Business Administration","generated_internal_id":"ASST_L-1"}],`+
				`"page_metadata":{"hasNext":false}}`)
			return
		}
		if slices.Contains(req.Filters.AwardTypeCodes, "A") {
			_, _ = io.WriteString(w, contractPages[req.Page])
			return
		}
		_, _ = io.WriteString(w, `{"results":[],"page_metadata":{"hasNext":false}}`)
	})

	u := NewUSASpending().(*usaspending)
	u.rlimit = rate.NewLimiter(rate.Inf, 1)
	u.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	u.awards = &awards{name: u.name + "-Awards-Handler", plugin: u}
	return u, sess
}

func TestAwardsStoresTheOrganizationsAwards(t *testing.T) {
	u, sess := newTestUSASpending(t)
	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: semantics.OrgNameKey("Acme Widgets, Inc.")})
	sess.Scope().Add(orgent.Asset)

	d := &plugintest.Dispatcher{}
	if err := u.awards.check(&et.Event{Entity: orgent, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}

	// Both contract pages and one page of each other award-type group.
	if reqs := sess.Web().Requests(); len(reqs) != 2+len(awardTypeGroups)-1 {
		t.Errorf("requests = %v", reqs)
	}

	got := map[string]float64{}
	for _, ev := range d.Events() {
		if f, ok := ev.Entity.Asset.(*oamfin.FundsTransfer); ok {
			got[f.ID] = f.Amount
		}
	}
	if len(got) != 3 || got["CONT_AWD_C-1"] != 250000 || got["usaspending:C-2"] != 5000 || got["ASST_L-1"] != 80000 {
		t.Fatalf("dispatched transfers = %v", got)
	}

	// Each award is received by the organization's account and names the
	// awarding agency as the third party.
	ctx := context.Background()
	for _, ev := range d.Events() {
		f := ev.Entity
		if recv, err := sess.DB().OutgoingEdges(ctx, f, time.Time{}, "recipient"); err != nil || len(recv) != 1 {
			t.Errorf("recipient edges of %v = %v, %v", f.Asset, recv, err)
		}
		tp, err := sess.DB().OutgoingEdges(ctx, f, time.Time{}, "third_party")
		if err != nil || len(tp) != 1 {
			t.Errorf("third_party edges of %v = %v, %v", f.Asset, tp, err)
			continue
		}
		agency, err := sess.DB().FindEntityById(ctx, tp[0].ToEntity.ID)
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := agency.Asset.(*oamorg.Organization); !ok {
			t.Errorf("the third party is %v, not an organization", agency.Asset)
		}
	}

	// Within the TTL the awards come back from the database.
	sent := len(sess.Web().Requests())
	d2 := &plugintest.Dispatcher{}
	if err := u.awards.check(&et.Event{Entity: orgent, Session: sess, Dispatcher: d2}); err != nil {
		t.Fatal(err)
	}
	if len(sess.Web().Requests()) != sent {
		t.Error("the API was asked again within the TTL")
	}
	if len(d2.Events()) != 3 {
		t.Errorf("transfers dispatched within the TTL = %v", d2.Names())
	}
}

func TestAwardsStopsAGroupOnAnError(t *testing.T) {
	u, sess := newTestUSASpending(t)
	// The API refuses a search for any other name.
	orgent := sess.Asset(t, &oamorg.Organization{ID: "other:test", Name: "other things"})
	sess.Scope().Add(orgent.Asset)

	d := &plugintest.Dispatcher{}
	if err := u.awards.check(&et.Event{Entity: orgent, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	if len(d.Events()) != 0 {
		t.Errorf("dispatched %v", d.Names())
	}
	// One failed request per group, no further pages.
	if reqs := sess.Web().Requests(); len(reqs) != len(awardTypeGroups) {
		t.Errorf("requests = %v", reqs)
	}
}

// Every award matched to the organization names the same Unique Entity ID,
// so it is stored as the organization's identifier; the foundation's awards,
// which do not match the name, do not make it ambiguous.
func TestAwardsStoreTheRecipientsUEI(t *testing.T) {
	u, sess := newTestUSASpending(t)
	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: semantics.OrgNameKey("Acme Widgets, Inc.")})
	sess.Scope().Add(orgent.Asset)

	if err := u.awards.check(&et.Event{Entity: orgent, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "id")
	if err != nil {
		t.Fatal(err)
	}

	var ueis []string
	for _, e := range edges {
		if ent, err := sess.DB().FindEntityById(ctx, e.ToEntity.ID); err == nil {
			if id, ok := ent.Asset.(*oamgen.Identifier); ok && id.Type == "uei" {
				ueis = append(ueis, id.ID)
			}
		}
	}
	if !slices.Equal(ueis, []string{"ACMEUEI12345"}) {
		t.Errorf("UEIs = %v, want ACMEUEI12345", ueis)
	}
}
