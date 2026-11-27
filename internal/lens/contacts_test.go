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

	// Attach contact attributes to OWASP's registrant contact record.
	add("ph1", "Phone", map[string]any{"e164": "+13155551000", "raw": "+13155551000"})
	add("em1", "Identifier", map[string]any{"id": "info@owasp.org", "id_type": "email"})
	add("loc1", "StreetAddress", map[string]any{"address": "100 Main Street", "city": "Utica", "province": "NY", "country": "US"})
	link("cr-owasp", "phone", "ph1")
	link("cr-owasp", "id", "em1")
	link("cr-owasp", "street_address", "loc1")

	r, err := FindContacts(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	if strings.Join(r.Phones, ",") != "+13155551000" {
		t.Errorf("phones = %+v", r.Phones)
	}
	if strings.Join(r.Emails, ",") != "info@owasp.org" {
		t.Errorf("emails = %+v", r.Emails)
	}
	if len(r.Addresses) != 1 || !strings.Contains(r.Addresses[0], "100 Main Street") ||
		!strings.Contains(r.Addresses[0], "Utica") {
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
	for _, want := range []string{"Phones:", "+13155551000", "info@owasp.org", "100 Main Street"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
}

func TestFindContactsNone(t *testing.T) {
	// utica.edu is outside OWASP's footprint and has no stored contact
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

func TestFindContactsMailboxesAndDocuments(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}

	// The email plugin's record for the domain, with mailboxes pointing in.
	add("cr-mail", "ContactRecord", map[string]any{"discovered_at": "owasp.org"})
	link("cr-mail", "fqdn", "owasp.org")
	add("em-safety", "Identifier", map[string]any{"id": "cusafety@owasp.org", "id_type": "email"})
	add("em-dean", "Identifier", map[string]any{"id": "dean@owasp.org", "id_type": "email"})
	link("em-safety", "registration_agency", "cr-mail")
	link("em-dean", "registration_agency", "cr-mail")
	// A record for another party that lists the domain is not the domain's
	// mailbox record.
	add("cr-other", "ContactRecord", map[string]any{"discovered_at": "https://vendor.example/contact"})
	link("cr-other", "fqdn", "owasp.org")
	add("em-vendor", "Identifier", map[string]any{"id": "sales@vendor.example", "id_type": "email"})
	link("em-vendor", "registration_agency", "cr-other")

	// A document on the domain that contains a mailbox and a phone.
	add("u-report", "URL", map[string]any{"url": "https://owasp.org/report.pdf", "host": "owasp.org"})
	link("u-report", "domain", "owasp.org")
	add("f-report", "File", map[string]any{"url": "https://owasp.org/report.pdf"})
	link("u-report", "file", "f-report")
	add("ph-report", "Phone", map[string]any{"e164": "+13155557333", "raw": "+13155557333"})
	link("f-report", "contains", "em-safety")
	link("f-report", "contains", "ph-report")

	r, err := FindContacts(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	emails := strings.Join(r.Emails, ",")
	for _, want := range []string{"cusafety@owasp.org", "dean@owasp.org"} {
		if !strings.Contains(emails, want) {
			t.Errorf("emails = %+v, want %s", r.Emails, want)
		}
	}
	if strings.Contains(emails, "sales@vendor.example") {
		t.Errorf("emails = %+v, want no mailbox from another party's record", r.Emails)
	}
	if !strings.Contains(strings.Join(r.Phones, ","), "+13155557333") {
		t.Errorf("phones = %+v, want the document's phone", r.Phones)
	}

	// The document is the more specific source, so it replaces "collected".
	if got := strings.Join(r.Sources["cusafety@owasp.org"], ","); got != contactFromDocument {
		t.Errorf("cusafety sources = %q", got)
	}
	if got := strings.Join(r.Sources["dean@owasp.org"], ","); got != contactFromDomain {
		t.Errorf("dean sources = %q", got)
	}
	if !strings.Contains(r.Text(), "cusafety@owasp.org ("+contactFromDocument+")") {
		t.Errorf("text lacks the source:\n%s", r.Text())
	}
}
