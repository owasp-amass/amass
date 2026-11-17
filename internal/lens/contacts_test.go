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

func TestFindContacts(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	// Attach contact attributes to Colgate's registrant contact record.
	add("ph1", "Phone", map[string]any{"e164": "+13152281000", "raw": "+13152281000"})
	add("em1", "Identifier", map[string]any{"id": "info@colgate.edu", "id_type": "email"})
	add("loc1", "Location", map[string]any{"address": "13 Oak Drive", "city": "Hamilton", "province": "NY", "country": "US"})
	link("cr-colgate", "phone", "ph1")
	link("cr-colgate", "id", "em1")
	link("cr-colgate", "location", "loc1")

	r, err := FindContacts(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if strings.Join(r.Phones, ",") != "+13152281000" {
		t.Errorf("phones = %+v", r.Phones)
	}
	if strings.Join(r.Emails, ",") != "info@colgate.edu" {
		t.Errorf("emails = %+v", r.Emails)
	}
	if len(r.Addresses) != 1 || !strings.Contains(r.Addresses[0], "13 Oak Drive") ||
		!strings.Contains(r.Addresses[0], "Hamilton") {
		t.Errorf("addresses = %+v", r.Addresses)
	}
	// The registrant contact's person is a contact.
	found := false
	for _, p := range r.People {
		if p == "Shared Person" {
			found = true
		}
	}
	if !found {
		t.Errorf("people = %+v (want Shared Person)", r.People)
	}

	text := r.Text()
	for _, want := range []string{"Phones:", "+13152281000", "info@colgate.edu", "13 Oak Drive"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestFindContactsNone(t *testing.T) {
	// hamilton.edu is outside Colgate's footprint and has no stored contact
	// attributes beyond the shared person; a fresh domain with no contacts
	// reports none.
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	// A domain owned by an org with no contact records at all.
	add("solo", "Organization", map[string]any{"name": "Solo Co"})
	add("solo.test", "FQDN", map[string]any{"name": "solo.test"})
	add("dr-solo", "DomainRecord", map[string]any{"domain": "solo.test"})
	add("cr-solo", "ContactRecord", nil)
	link("cr-solo", "organization", "solo")
	link("dr-solo", "registrant_contact", "cr-solo")
	link("solo.test", "registration", "dr-solo")

	r, err := FindContacts(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["solo.test"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Phones)+len(r.Emails)+len(r.Addresses) != 0 {
		t.Errorf("expected no phones/emails/addresses, got %+v", r)
	}
	if !strings.Contains(r.Text(), "No contact details are stored") {
		t.Errorf("unexpected text:\n%s", r.Text())
	}
}
