// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

// grantsSession serves the three grant APIs; each names the organization,
// another recipient, and one award twice or with no amount.
func grantsSession(t *testing.T) *plugintest.Session {
	t.Helper()

	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Web().Reply("GET api.nsf.gov/services/v1/awards.json", http.StatusOK, `{"response":{"award":[
	  {"id":"1","awardeeName":"OWASP Foundation","fundsObligatedAmt":"450000","date":"03/01/2023"},
	  {"id":"1","awardeeName":"OWASP Foundation","fundsObligatedAmt":"450000","date":"03/01/2023"},
	  {"id":"2","awardeeName":"OWASP Foundation","fundsObligatedAmt":"","date":"09/15/2022"},
	  {"id":"3","awardeeName":"OWASP Research LLC","fundsObligatedAmt":"9","date":"09/15/2022"}
	]}}`)
	sess.Web().Handle("POST api.reporter.nih.gov/v2/projects/search", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"org_names":["owasp foundation"]`) {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = io.WriteString(w, `{"results":[
		  {"project_num":"R01-1","direct_cost_amt":200000,"indirect_cost_amt":96920,
		   "organization":{"org_name":"OWASP FOUNDATION"},"fiscal_year":2023}
		]}`)
	})
	old := sbirBulk
	sbirBulk = newSBIRIndex(t.TempDir(), sbirBulkURL)
	t.Cleanup(func() { sbirBulk = old })
	sess.Web().Reply("GET data.www.sbir.gov/mod_awarddatapublic_no_abstract/award_data_no_abstract.csv", http.StatusOK,
		"Company,Award Title,Agency,Branch,Phase,Program,Agency Tracking Number,Contract,Proposal Award Date,"+
			"Contract End Date,Solicitation Number,Solicitation Year,Solicitation Close Date,Proposal Submitted Date,"+
			"Date of Notification,Topic Code,Award Year,Award Amount\n"+
			"OWASP Foundation,Gadget Study,DOD,,Phase I,SBIR,,,,,,,,,,,2022,\"$750,000.00\"\n"+
			"OWASP Foundation,,DOD,,Phase I,SBIR,,,,,,,,,,,,5\n"+
			"OWASP Research LLC,Widget,NASA,,Phase I,SBIR,,NNX-1,2021-05-01,,,,,,,,2021,90000\n")
	return sess
}

func TestGrantSourcesStoreTheOrganizationsGrants(t *testing.T) {
	for _, c := range []struct {
		plugin *source
		want   map[string]float64
	}{
		{NewNSF().(*source), map[string]float64{"nsf:1": 450000}},
		{NewNIH().(*source), map[string]float64{"nih:R01-1": 296920}},
		{NewSBIR().(*source), map[string]float64{"sbir:Gadget_Study:2022": 750000}},
	} {
		t.Run(c.plugin.name, func(t *testing.T) {
			sess := grantsSession(t)
			h := c.plugin
			h.rlimit = rate.NewLimiter(rate.Inf, 1)

			orgent := sess.Asset(t, &oamorg.Organization{ID: "owasp:test", Name: "owasp foundation"})
			sess.Scope().Add(orgent.Asset)
			d := &plugintest.Dispatcher{}
			e := &et.Event{Entity: orgent, Session: sess, Dispatcher: d}
			if err := h.check(e); err != nil {
				t.Fatal(err)
			}

			got := map[string]float64{}
			for _, ev := range d.Events() {
				if f, ok := ev.Entity.Asset.(*oamfin.FundsTransfer); ok {
					got[f.ID] = f.Amount
				}
			}
			if len(got) != len(c.want) {
				t.Fatalf("transfers = %v, want %v; requests %v", got, c.want, sess.Web().Requests())
			}
			for id, amt := range c.want {
				if got[id] != amt {
					t.Errorf("transfer %s = %v, want %v", id, got[id], amt)
				}
			}

			// The funding agency is the third party of each grant.
			ctx := context.Background()
			for _, ev := range d.Events() {
				if tp, err := sess.DB().OutgoingEdges(ctx, ev.Entity, time.Time{}, "third_party"); err != nil || len(tp) != 1 {
					t.Errorf("third_party edges of %v = %v, %v", ev.Entity.Asset, tp, err)
				}
			}

			// The organization is monitored: no second query within the TTL.
			if err := h.check(e); err != nil {
				t.Fatal(err)
			}
			if reqs := sess.Web().Requests(); len(reqs) != 1 {
				t.Errorf("requests = %v", reqs)
			}
		})
	}
}
