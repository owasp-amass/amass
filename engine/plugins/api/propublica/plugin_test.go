// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package propublica

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

func TestFilingsCollectsTheNonprofit(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Web().Reply("GET projects.propublica.org/nonprofits/api/v2/search.json", http.StatusOK,
		`{"organizations":[{"ein":131234567,"name":"Utica Products Foundation"},{"ein":990000001,"name":"UTICA UNIVERSITY"}]}`)
	sess.Web().Reply("GET projects.propublica.org/nonprofits/api/v2/organizations/990000001.json", http.StatusOK,
		`{"organization":{"ein":990000001,"strein":"99-0000001","name":"Utica University",
		  "address":"100 Main Street","city":"Utica","state":"NY","zipcode":"13502"},
		  "filings_with_data":[
		    {"tax_prd_yr":2022,"totcntrbgfts":120000000},
		    {"tax_prd_yr":2021,"totcntrbgfts":"95000000"},
		    {"tax_prd_yr":2020,"totcntrbgfts":0}
		  ]}`)

	p := NewProPublica().(*propublica)
	p.rlimit = rate.NewLimiter(rate.Inf, 1)
	p.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	p.filings = &filings{name: p.name + "-Filings-Handler", plugin: p}

	orgent := sess.Asset(t, &oamorg.Organization{ID: "utica:test", Name: "utica university"})
	sess.Scope().Add(orgent.Asset)
	e := &et.Event{Entity: orgent, Session: sess, Dispatcher: &plugintest.Dispatcher{}}
	if err := p.filings.check(e); err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	var ein string
	if edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if ent, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
				if id, ok := ent.Asset.(*general.Identifier); ok && id.Type == EINIdentifier {
					ein = id.ID
				}
			}
		}
	}
	if ein != "99-0000001" {
		t.Errorf("EIN = %q; requests %v", ein, sess.Web().Requests())
	}

	// The address is reached through a ContactRecord naming the organization.
	crs, err := sess.DB().IncomingEdges(ctx, orgent, time.Time{}, "organization")
	if err != nil || len(crs) != 1 {
		t.Fatalf("contact records = %v, %v", crs, err)
	}
	cr, _ := sess.DB().FindEntityById(ctx, crs[0].FromEntity.ID)
	addrs, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "street_address")
	if err != nil || len(addrs) != 1 {
		t.Fatalf("addresses = %v, %v", addrs, err)
	}
	// The address is in the standard form a parsed address has, in the US.
	if a, _ := sess.DB().FindEntityById(ctx, addrs[0].ToEntity.ID); a.Asset.(*contact.StreetAddress).City != "utica" ||
		a.Asset.(*contact.StreetAddress).Country != "US" ||
		!strings.HasSuffix(a.Asset.(*contact.StreetAddress).Address, ", UTICA, NY 13502, US") {
		t.Errorf("address = %+v", a.Asset)
	}

	// The two filings that report contributions are received by the
	// organization's account; the zero filing is not stored.
	got := map[string]float64{}
	for _, ent := range org.OrgTransfersReceived(sess, orgent, time.Now().Add(-time.Hour), p.source) {
		f := ent.Asset.(*oamfin.FundsTransfer)
		got[f.ID] = f.Amount
	}
	if len(got) != 2 || got["irs990:99-0000001:2022"] != 120000000 || got["irs990:99-0000001:2021"] != 95000000 {
		t.Errorf("transfers = %v", got)
	}

	// Within the TTL the organization is not looked up again.
	sent := len(sess.Web().Requests())
	if err := p.filings.check(e); err != nil {
		t.Fatal(err)
	}
	if len(sess.Web().Requests()) != sent {
		t.Error("ProPublica was asked again within the TTL")
	}
}

func TestFilingsSkipsADifferentNonprofit(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Web().Reply("GET projects.propublica.org/nonprofits/api/v2/search.json", http.StatusOK,
		`{"organizations":[{"ein":131234567,"name":"Utica Products Foundation"}]}`)

	p := NewProPublica().(*propublica)
	p.rlimit = rate.NewLimiter(rate.Inf, 1)
	p.filings = &filings{name: p.name + "-Filings-Handler", plugin: p}

	orgent := sess.Asset(t, &oamorg.Organization{ID: "utica:test", Name: "utica university"})
	sess.Scope().Add(orgent.Asset)
	if err := p.filings.check(&et.Event{Entity: orgent, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}
	if reqs := sess.Web().Requests(); len(reqs) != 1 {
		t.Errorf("the organization record was fetched for a different nonprofit: %v", reqs)
	}
}
