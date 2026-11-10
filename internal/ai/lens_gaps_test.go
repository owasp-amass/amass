// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"strings"
	"testing"
)

// campusGapsFixture adds unattributed assets to the campus: a registrant
// contact sharing Colgate's phone and address (identity), a name resolving
// into Colgate's netblock (hosting), a name on Colgate's certificate that
// also resolves there (co-listing and hosting), and a Hamilton College name
// pointing into Colgate's network (controlled elsewhere, not a gap).
func campusGapsFixture() vendorGraph {
	g := vendorFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }

	add("phone", "Phone", "+1.3152287000", map[string]any{"e164": "+1.3152287000"})
	add("loc", "Location", "13 Oak Drive, Hamilton NY", map[string]any{"address": "13 Oak Drive, Hamilton NY"})
	link("cr-colgate", "phone", "phone", "SimpleRelation")
	link("cr-colgate", "location", "loc", "SimpleRelation")

	add("cr-alt", "ContactRecord", "https://rdap.example/alumni", nil)
	add("dr-alt", "DomainRecord", "colgatealumni.org", map[string]any{"domain": "colgatealumni.org"})
	named("colgatealumni.org", "FQDN", "colgatealumni.org")
	link("cr-alt", "phone", "phone", "SimpleRelation")
	link("cr-alt", "location", "loc", "SimpleRelation")
	link("dr-alt", "registrant_contact", "cr-alt", "SimpleRelation")
	link("colgatealumni.org", "registration", "dr-alt", "SimpleRelation")

	named("raiders.example.net", "FQDN", "raiders.example.net")
	link("raiders.example.net", "dns_record", "ip-own", "BasicDNSRelation")

	named("colgate-events.com", "FQDN", "colgate-events.com")
	link("cert", "san_dns_name", "colgate-events.com", "SimpleRelation")
	link("colgate-events.com", "dns_record", "ip-own", "BasicDNSRelation")

	link("www.hamilton.edu", "dns_record", "ip-own", "BasicDNSRelation")
	return g
}

func gapReport(t *testing.T) OwnershipGapReport {
	t.Helper()

	r, err := searchOwnershipGaps(context.Background(), campusGapsFixture(), vendorCatalog{testOAMCatalog},
		campusGapsFixture().assets["colgate"])
	if err != nil {
		t.Fatal(err)
	}

	return r
}

func gapCandidate(r OwnershipGapReport, asset string) *GapCandidate {
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
	if c.Decision != GapPropose || len(c.Signals) != 2 || c.Signals[0].Kind != SignalIdentity {
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
	if c == nil || c.Decision != GapWeak || c.Attachment != nil {
		t.Fatalf("candidate = %+v, want weak with no attachment", c)
	}
}

func TestHostingPlusColistingNeedsReview(t *testing.T) {
	c := gapCandidate(gapReport(t), "colgate-events.com")
	if c == nil || c.Decision != GapReview {
		t.Fatalf("candidate = %+v, want review", c)
	}

	kinds := map[string]bool{}
	for _, s := range c.Signals {
		kinds[s.Kind] = true
	}
	if !kinds[SignalHosting] || !kinds[SignalColisting] {
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
	inv, err := (Agent{Runner: ToolRunner{Graph: campusGapsFixture(), Catalog: vendorCatalog{testOAMCatalog},
		Limits: DefaultLimits()}}).AskQuery(context.Background(),
		Query{Version: QueryVersion, Subject: PlanSubject{Type: "Organization", Name: "Colgate University"},
			Traversal: TraversalExplore, Direction: "both", Purpose: "connected", Lens: LensOwnershipGaps,
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
