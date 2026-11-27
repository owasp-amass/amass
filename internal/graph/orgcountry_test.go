// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph_test

import (
	"context"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// orgCountryFixture builds an organization with the contact evidence given:
// a location country code and a phone country code (either may be "").
func orgCountryFixture(name, jurisdiction, locCountry, phoneCountry string) (graphtest.FakeGraph, string) {
	og := graphtest.NewOrgGraph()
	og.Org("org", name, "", jurisdiction, "")
	if locCountry != "" {
		og.Graph.Assets["loc"] = graph.Asset{ID: "loc", Type: "StreetAddress", Key: "loc",
			Content: map[string]any{"country": locCountry, "city": "Somewhere"}}
		og.Contact("org", "cr", "loc")
	} else {
		og.Contact("org", "cr", "")
	}
	if phoneCountry != "" {
		og.Graph.Assets["ph"] = graph.Asset{ID: "ph", Type: "Phone", Key: "+0",
			Content: map[string]any{"country_abbrev": phoneCountry}}
		og.Link("cr", "ph", "phone")
	}
	return og.Graph, "org"
}

func TestOrgCountryJurisdictionWins(t *testing.T) {
	// Jurisdiction (US-DE) is authoritative even when an address says otherwise.
	g, id := orgCountryFixture("Acme Corp", "US-DE", "MX", "")
	ev, ok, err := graph.OrgCountry(context.Background(), g, id)
	if err != nil || !ok {
		t.Fatalf("OrgCountry: ok=%v err=%v", ok, err)
	}
	if ev.Country != "US" || ev.Signal != "jurisdiction" || ev.Confidence != 95 {
		t.Fatalf("got %+v, want US/jurisdiction/95", ev)
	}

	cs, err := graph.OrgCountries(context.Background(), g, id, 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(cs) != 2 || cs[0].Country != "US" || cs[1].Country != "MX" {
		t.Fatalf("got %+v, want [US, MX]", cs)
	}
}

func TestOrgCountryContactFallbackAgrees(t *testing.T) {
	// The CEMEX case: no jurisdiction, but a Mexican address and a +52 phone
	// agree, so the registration-location signal (75) is raised by agreement.
	g, id := orgCountryFixture("cemex central sa de cv", "", "MX", "MX")
	ev, ok, err := graph.OrgCountry(context.Background(), g, id)
	if err != nil || !ok {
		t.Fatalf("OrgCountry: ok=%v err=%v", ok, err)
	}
	if ev.Country != "MX" {
		t.Fatalf("got %q, want MX", ev.Country)
	}
	if ev.Signal != "registration_location" {
		t.Fatalf("strongest signal = %q, want registration_location", ev.Signal)
	}
	if ev.Confidence != 80 { // 75 + one extra agreeing signal * boost 5
		t.Fatalf("confidence = %d, want 80", ev.Confidence)
	}
	if len(ev.Signals) != 2 {
		t.Fatalf("agreeing signals = %v, want 2", ev.Signals)
	}
}

func TestOrgCountryPhoneOnly(t *testing.T) {
	g, id := orgCountryFixture("Globex", "", "", "MX")
	ev, ok, err := graph.OrgCountry(context.Background(), g, id)
	if err != nil || !ok {
		t.Fatalf("OrgCountry: ok=%v err=%v", ok, err)
	}
	if ev.Country != "MX" || ev.Signal != "registrant_phone" || ev.Confidence != 55 {
		t.Fatalf("got %+v, want MX/registrant_phone/55", ev)
	}
}

func TestOrgCountryRejectsFullCountryName(t *testing.T) {
	// A geocoder's full country name is not an ISO alpha-2 code, so it is
	// ignored rather than mismatched; with no other signal, none is found.
	g, id := orgCountryFixture("Initech", "", "Mexico", "")
	if _, ok, err := graph.OrgCountry(context.Background(), g, id); ok || err != nil {
		t.Fatalf("expected no country, got ok=%v err=%v", ok, err)
	}
}

func TestOrgCountryNoneWhenUnknown(t *testing.T) {
	g, _ := orgCountryFixture("Nobody", "", "", "")
	if cs, err := graph.OrgCountries(context.Background(), g, "missing", 0); err != nil || len(cs) != 0 {
		t.Fatalf("expected none for a missing org, got %+v err=%v", cs, err)
	}
}
