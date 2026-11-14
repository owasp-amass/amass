// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func gapReport(t *testing.T) lens.OwnershipGapReport {
	t.Helper()

	r, err := lens.SearchOwnershipGaps(context.Background(), graphtest.CampusGapsFixture(), graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		graphtest.CampusGapsFixture().Assets["colgate"])
	if err != nil {
		t.Fatal(err)
	}

	return r
}

func gapCandidate(r lens.OwnershipGapReport, asset string) *lens.GapCandidate {
	for i, c := range r.Candidates {
		if c.Asset == asset {
			return &r.Candidates[i]
		}
	}

	return nil
}

func TestSharedRegistrantDetailsAreProposed(t *testing.T) {
	r := gapReport(t)
	c := gapCandidate(r, "https://rdap.example/alumni")
	if c == nil {
		t.Fatalf("shared-identity contact not found: %+v", r.Candidates)
	}
	if c.Decision != lens.GapPropose || len(c.Signals) != 2 || c.Signals[0].Kind != lens.SignalIdentity {
		t.Errorf("candidate = %+v, want propose on two identity signals", c)
	}
	if c.Attachment == nil || c.Attachment.String() !=
		"ContactRecord https://rdap.example/alumni --organization--> Organization Colgate University" {
		t.Errorf("attachment = %v", c.Attachment)
	}
	if strings.Join(c.Gains, ",") != "DomainRecord colgatealumni.org,FQDN colgatealumni.org" {
		t.Errorf("gains = %v", c.Gains)
	}
}

func TestHostingAloneIsWeakAndUnattachable(t *testing.T) {
	c := gapCandidate(gapReport(t), "raiders.example.net")
	if c == nil || c.Decision != lens.GapWeak || c.Attachment != nil {
		t.Fatalf("candidate = %+v, want weak with no attachment", c)
	}
}

func TestHostingPlusColistingNeedsReview(t *testing.T) {
	c := gapCandidate(gapReport(t), "colgate-events.com")
	if c == nil || c.Decision != lens.GapReview {
		t.Fatalf("candidate = %+v, want review", c)
	}

	kinds := map[string]bool{}
	for _, s := range c.Signals {
		kinds[s.Kind] = true
	}
	if !kinds[lens.SignalHosting] || !kinds[lens.SignalColisting] {
		t.Errorf("signals = %+v, want hosting and co-listing", c.Signals)
	}
}

func TestAssetsControlledElsewhereAreNotGaps(t *testing.T) {
	r := gapReport(t)
	for _, c := range r.Candidates {
		if strings.Contains(c.Asset, "hamilton") || strings.Contains(c.Asset, "colgate.edu") {
			t.Errorf("documented asset reported as a gap: %+v", c)
		}
	}
}

func TestGapAnswerAndEvidence(t *testing.T) {
	inv, err := (Agent{Runner: ToolRunner{Graph: graphtest.CampusGapsFixture(), Catalog: graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		Limits: graph.DefaultLimits()}}).AskQuery(context.Background(),
		Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "Colgate University"},
			Traversal: TraversalExplore, Direction: "both", Purpose: "connected", Lens: lens.LensOwnershipGaps,
			Source: SourceCaller}, AdaptiveOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(inv.Answer, "[propose 0.90] ContactRecord https://rdap.example/alumni: identity; "+
		"would record ContactRecord https://rdap.example/alumni --organization--> Organization Colgate University") ||
		!strings.Contains(inv.Answer, "Nothing has been written.") {
		t.Errorf("answer:\n%s", inv.Answer)
	}

	text := BuildEvidenceBundle(inv, 200).String()
	if !strings.Contains(text, "ContactRecord https://rdap.example/alumni --phone--> Phone +1.3152287000") {
		t.Errorf("evidence lacks the shared phone:\n%s", text)
	}
}

func TestRedactedValuesGiveNoIdentitySignal(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	g.Assets["loc"] = graph.Asset{ID: "loc", Type: "Location", Key: "REDACTED FOR PRIVACY",
		Content: map[string]any{"address": "REDACTED FOR PRIVACY"}}
	g.Assets["phone"] = graph.Asset{ID: "phone", Type: "Phone", Key: "REDACTED FOR PRIVACY",
		Content: map[string]any{"e164": "REDACTED FOR PRIVACY"}}

	r, err := lens.SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate"])
	if err != nil {
		t.Fatal(err)
	}
	if c := gapCandidate(r, "https://rdap.example/alumni"); c != nil {
		t.Errorf("a contact sharing only redacted values became a candidate: %+v", c)
	}
}

func TestReverseLookupNamesAreNotCandidates(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	g.Assets["rev"] = graph.Asset{ID: "rev", Type: "FQDN", Key: "1.1.43.149.in-addr.arpa",
		Content: map[string]any{"name": "1.1.43.149.in-addr.arpa"}}
	g.Links = append(g.Links, graph.Relation{ID: "rev-ip", FromID: "rev", ToID: "ip-own", Label: "dns_record",
		Type: "BasicDNSRelation"})

	r, err := lens.SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate"])
	if err != nil {
		t.Fatal(err)
	}
	if c := gapCandidate(r, "1.1.43.149.in-addr.arpa"); c != nil {
		t.Errorf("a reverse-DNS lookup name became a candidate: %+v", c)
	}
	if c := gapCandidate(r, "raiders.example.net"); c == nil {
		t.Error("the ordinary hosted name is no longer a candidate")
	}
}

func TestLargeGainsAreCounted(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	for i := 0; i < lens.GapMaxGains+5; i++ {
		id := fmt.Sprintf("alumni-%02d.colgatealumni.org", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: id, Content: map[string]any{"name": id}}
		g.Links = append(g.Links, graph.Relation{ID: "node-" + id, FromID: "colgatealumni.org", ToID: id, Label: "node",
			Type: "SimpleRelation"})
	}

	r, err := lens.SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate"])
	if err != nil {
		t.Fatal(err)
	}

	c := gapCandidate(r, "https://rdap.example/alumni")
	if c == nil || len(c.GainAssets) != lens.GapMaxGains || len(c.Gains) != lens.GapMaxGains+1 ||
		!strings.HasPrefix(c.Gains[lens.GapMaxGains], "and ") {
		t.Fatalf("gains = %v (%d assets)", c.Gains, len(c.GainAssets))
	}
}

func TestAddressesInOwnedNetblocksAreOwned(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	// An address in Colgate's 149.43.0.0/16 that the lens never read as
	// contained (a large netblock), and one outside it.
	for id, addr := range map[string]string{"ip-unread": "149.43.200.9", "ip-outside": "198.51.100.9"} {
		g.Assets[id] = graph.Asset{ID: id, Type: "IPAddress", Key: addr, Content: map[string]any{"address": addr}}
		g.Links = append(g.Links, graph.Relation{ID: id + "-ptr", FromID: id, ToID: "portal.colgate.edu", Label: "ptr_record",
			Type: "SimpleRelation"})
	}

	r, err := lens.SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate"])
	if err != nil {
		t.Fatal(err)
	}
	if c := gapCandidate(r, "149.43.200.9"); c != nil {
		t.Errorf("an address in an owned netblock became a candidate: %+v", c)
	}
	if c := gapCandidate(r, "198.51.100.9"); c == nil {
		t.Error("an address outside the owned netblocks is no longer a candidate")
	}
}
