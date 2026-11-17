// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
)

// TestContentFloatReadsTypedAsset guards the funding lens against the amount
// disappearing when an asset's content is a typed struct (as the engine stores
// it) rather than a map: the field must still be read. A regression for NIH
// FundsTransfers showing no dollar amount.
func TestContentFloatReadsTypedAsset(t *testing.T) {
	typed := graph.Asset{ID: "1", Type: "FundsTransfer", Key: "nih:X",
		Content: &oamfin.FundsTransfer{ID: "nih:X", Amount: 296920, Currency: "USD",
			ReferenceNumber: "nih:X", ExchangeDate: "2023-08-01T00:00:00"}}
	if got := contentFloat(typed, "amount"); got != 296920 {
		t.Errorf("typed content amount = %v, want 296920", got)
	}

	asMap := graph.Asset{ID: "2", Type: "FundsTransfer", Key: "m",
		Content: map[string]any{"amount": 5000.0}}
	if got := contentFloat(asMap, "amount"); got != 5000 {
		t.Errorf("map content amount = %v, want 5000", got)
	}
}

func TestFindFunding(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	// Colgate holds a checking account; a seed account funds two rounds.
	// Sequoia holds the seed account (an investor reached through it) and
	// Benchmark is named directly on the second round.
	add("acct-colgate", "Account", map[string]any{"unique_id": "colgate:checking"})
	add("acct-seed", "Account", map[string]any{"unique_id": "aviato:seed"})
	g.Assets["sequoia"] = graph.Asset{ID: "sequoia", Type: "Organization", Key: "Sequoia Capital",
		Content: map[string]any{"name": "Sequoia Capital"}}
	g.Assets["benchmark"] = graph.Asset{ID: "benchmark", Type: "Organization", Key: "Benchmark",
		Content: map[string]any{"name": "Benchmark"}}
	g.Assets["ft-a"] = graph.Asset{ID: "ft-a", Type: "FundsTransfer", Key: "Colgate University:Series A",
		Content: map[string]any{"amount": 5_000_000.0, "currency": "USD", "exchange_date": "2023-06-01"}}
	g.Assets["ft-b"] = graph.Asset{ID: "ft-b", Type: "FundsTransfer", Key: "Colgate University:Series B",
		Content: map[string]any{"amount": 12_000_000.0, "currency": "USD", "exchange_date": "2024-09-15"}}

	link("colgate", "account", "acct-colgate")
	link("sequoia", "account", "acct-seed")
	link("ft-a", "recipient", "acct-colgate")
	link("ft-a", "sender", "acct-seed")
	link("ft-b", "recipient", "acct-colgate")
	link("ft-b", "sender", "acct-seed")
	link("ft-b", "third_party", "benchmark")

	r, err := FindFunding(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Rounds) != 2 {
		t.Fatalf("rounds = %+v", r.Rounds)
	}
	// Most recent round first.
	if r.Rounds[0].Round != "Colgate University:Series B" || r.Rounds[0].Amount != 12_000_000 {
		t.Errorf("first round = %+v", r.Rounds[0])
	}
	if r.Total != 17_000_000 || r.Currency != "USD" {
		t.Errorf("total = %v %s", r.Total, r.Currency)
	}
	// Sequoia is reached through the seed account; Benchmark is named on the
	// round directly. The recipient (Colgate) is not an investor.
	want := map[string]bool{"Sequoia Capital": true, "Benchmark": true}
	if len(r.Investors) != 2 {
		t.Fatalf("investors = %+v", r.Investors)
	}
	for _, inv := range r.Investors {
		if !want[inv] {
			t.Errorf("unexpected investor %q", inv)
		}
	}
	// The Series B round names both its direct and account-reached investors.
	for _, rd := range r.Rounds {
		if rd.Round == "Colgate University:Series B" {
			if len(rd.Investors) != 2 {
				t.Errorf("series B investors = %+v", rd.Investors)
			}
		}
	}

	text := r.Text()
	for _, want := range []string{"Series B", "12.0M USD", "Sequoia Capital", "Total raised: 17.0M USD"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestFindFundingNone(t *testing.T) {
	g := graphtest.VendorFixture()
	r, err := FindFunding(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Rounds) != 0 {
		t.Fatalf("expected no rounds, got %+v", r.Rounds)
	}
	if !strings.Contains(r.Text(), "No funding record is stored") {
		t.Errorf("unexpected text:\n%s", r.Text())
	}
}
