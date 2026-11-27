// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ted

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
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

func TestAwardsStoresTheWinnersContracts(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	var query string
	sess.Web().Handle("POST api.ted.europa.eu/v3/notices/search", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Query string `json:"query"`
		}
		body, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(body, &req)
		query = req.Query

		_, _ = io.WriteString(w, `{"notices":[
		  {"publication-number":"100-2024","winner-name":{"deu":["ACME OY"]},"buyer-name":{"deu":["Stadt Kiel"]},
		   "total-value":125000,"total-value-cur":"EUR","publication-date":"2024-03-01+01:00"},
		  {"publication-number":"100-2024","winner-name":["Acme Oy"],"total-value":125000},
		  {"publication-number":"200-2024","winner-name":["Acme Oy"],"tender-value":"40000","tender-value-cur":["SEK"],
		   "buyer-name":["Göteborgs Stad"],"winner-decision-date":"2024-01-10"},
		  {"publication-number":"300-2024","winner-name":["Acme Services Oy"],"total-value":99},
		  {"publication-number":"400-2024","winner-name":["Acme Oy"]}
		]}`)
	})

	p := NewTED().(*ted)
	p.rlimit = rate.NewLimiter(rate.Inf, 1)
	p.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	p.awards = &awards{name: p.name + "-Awards-Handler", plugin: p}

	orgent := sess.Asset(t, &oamorg.Organization{ID: "acme:test", Name: "acme"})
	sess.Scope().Add(orgent.Asset)
	d := &plugintest.Dispatcher{}
	e := &et.Event{Entity: orgent, Session: sess, Dispatcher: d}
	if err := p.awards.check(e); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(query, `winner-name="acme"`) {
		t.Errorf("query = %q", query)
	}

	// The repeated notice is stored once, the other winner and the notice
	// with no value are not stored.
	got := map[string]*oamfin.FundsTransfer{}
	for _, ev := range d.Events() {
		if f, ok := ev.Entity.Asset.(*oamfin.FundsTransfer); ok {
			got[f.ID] = f
		}
	}
	if len(got) != 2 {
		t.Fatalf("transfers = %v", d.Names())
	}
	if f := got["ted:100-2024"]; f == nil || f.Amount != 125000 || f.Currency != "EUR" {
		t.Errorf("the total-value award = %+v", f)
	}
	if f := got["ted:200-2024"]; f == nil || f.Amount != 40000 || f.Currency != "SEK" {
		t.Errorf("the tender-value award = %+v", f)
	}

	// Each award names its buyer as the third party.
	ctx := context.Background()
	for _, ev := range d.Events() {
		tp, err := sess.DB().OutgoingEdges(ctx, ev.Entity, time.Time{}, "third_party")
		if err != nil || len(tp) != 1 {
			t.Errorf("third_party edges of %v = %v, %v", ev.Entity.Asset, tp, err)
		}
	}

	// The organization is monitored: no second search within the TTL.
	if err := p.awards.check(e); err != nil {
		t.Fatal(err)
	}
	if reqs := sess.Web().Requests(); len(reqs) != 1 {
		t.Errorf("requests = %v", reqs)
	}
}
