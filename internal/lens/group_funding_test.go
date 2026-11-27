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
)

// TestFindGroupFunding checks that the rollup merges the funding of every
// organization in a corporate group, attributes each round to the organization
// that received it, and totals across the group. This is the case a plain
// funding lens misses: funding split across a parent and its unit.
func TestFindGroupFunding(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	org := func(id, name string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "Organization", Key: name,
			Content: map[string]any{"name": name}}
	}
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	// A university system and a campus unit beneath it, each with its own
	// account and funding from a different agency.
	org("system", "Example State University System")
	org("campus", "Example Polytechnic Institute")
	org("nsf", "National Science Foundation")
	org("nih", "National Institutes of Health")
	link("system", "org_unit", "campus")

	add("acct-system", "Account", map[string]any{"unique_id": "system:checking"})
	add("acct-campus", "Account", map[string]any{"unique_id": "campus:checking"})
	link("system", "account", "acct-system")
	link("campus", "account", "acct-campus")

	add("ft-system", "FundsTransfer", map[string]any{"amount": 1_000_000.0, "currency": "USD",
		"exchange_date": "2023-01-01"})
	add("ft-campus", "FundsTransfer", map[string]any{"amount": 250_000.0, "currency": "USD",
		"exchange_date": "2022-05-01"})
	link("ft-system", "recipient", "acct-system")
	link("ft-system", "third_party", "nsf")
	link("ft-campus", "recipient", "acct-campus")
	link("ft-campus", "third_party", "nih")

	schema := graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
	r, err := FindGroupFunding(context.Background(), g, schema, g.Assets["system"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if len(r.Rounds) != 2 {
		t.Fatalf("rounds = %d, want 2: %+v", len(r.Rounds), r.Rounds)
	}
	if r.Total != 1_250_000 || r.Currency != "USD" {
		t.Errorf("group total = %v %s, want 1250000 USD", r.Total, r.Currency)
	}

	// Each round is credited to the organization that received it.
	recipientOf := map[string]string{}
	for _, rd := range r.Rounds {
		recipientOf[rd.Round] = rd.Recipient
	}
	if got := recipientOf[graph.AssetLabel(g.Assets["ft-system"])]; got != "Example State University System" {
		t.Errorf("system round recipient = %q", got)
	}
	if got := recipientOf[graph.AssetLabel(g.Assets["ft-campus"])]; got != "Example Polytechnic Institute" {
		t.Errorf("campus round recipient = %q", got)
	}

	investors := strings.Join(r.Investors, ",")
	if !strings.Contains(investors, "National Science Foundation") ||
		!strings.Contains(investors, "National Institutes of Health") {
		t.Errorf("investors = %q, want both agencies", investors)
	}

	if len(r.Recipients) != 2 {
		t.Errorf("recipients = %d, want 2: %+v", len(r.Recipients), r.Recipients)
	}
}

func TestGroupFundingTotalCurrency(t *testing.T) {
	r := GroupFundingReport{Rounds: []GroupFundingRound{
		{FundingRound: FundingRound{Round: "a", Amount: 100, Currency: "USD"}},
		{FundingRound: FundingRound{Round: "b", Amount: 50, Currency: "USD"}},
		{FundingRound: FundingRound{Round: "c", Amount: 0, Currency: ""}}, // no amount: ignored
	}}
	if sum, cur := r.groupTotal(); sum != 150 || cur != "USD" {
		t.Errorf("single-currency total = %v %s, want 150 USD", sum, cur)
	}

	// A second currency makes the group total undefined.
	r.Rounds = append(r.Rounds, GroupFundingRound{FundingRound: FundingRound{Round: "d", Amount: 10, Currency: "EUR"}})
	if sum, cur := r.groupTotal(); sum != 0 || cur != "" {
		t.Errorf("mixed-currency total = %v %s, want 0 (unset)", sum, cur)
	}
}

func TestGroupFundingTextEmpty(t *testing.T) {
	var r GroupFundingReport
	if txt := r.Text(); !strings.Contains(txt, "No funding record is stored for the group") {
		t.Errorf("empty group text = %q", txt)
	}
}
