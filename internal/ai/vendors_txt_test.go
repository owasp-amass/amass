// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
	"github.com/owasp-amass/amass/v5/internal/ai/lens"
)

func TestFindVendorsReportsVerificationsAndUnrecognizedRecords(t *testing.T) {
	g := aitest.VendorFixture()
	g.Assets["google"] = graph.Asset{ID: "google", Type: "Organization", Key: "Google LLC",
		Content: map[string]any{"name": "Google LLC"}}
	g.Links = append(g.Links, graph.Relation{ID: "colgate.edu-verified_for-google", FromID: "colgate.edu", ToID: "google",
		Label: lens.VerifiedForLabel, Type: "SimpleRelation"})
	txt := func(id, data string) graph.Evidence {
		return graph.Evidence{ID: id, SubjectID: "colgate.edu", Kind: "property", Property: map[string]any{
			"property_name": graph.DNSRecordProperty, "header": map[string]any{"rr_type": graph.RRTypeTXT}, "data": data}}
	}
	g.EvidenceByID = map[string][]graph.Evidence{"colgate.edu": {
		txt("t1", "google-site-verification=abc123"),
		txt("t2", "acme-domain-verification=xyz"),
		txt("t3", "v=spf1 include:_spf.google.com include:spf.acme-mailer.example -all"),
	}}

	known := func(r string) bool { return strings.HasPrefix(r, "google-site-verification=") }
	r, err := lens.FindVendors(context.Background(), g, aitest.VendorCatalog{PlanCatalog: aitest.TestOAMCatalog}, g.Assets["colgate.edu"],
		lens.VendorOptions{KnownVerification: known})
	if err != nil {
		t.Fatal(err)
	}

	googles := 0
	for _, v := range r.Vendors {
		if v.Vendor == "Google LLC" {
			googles++
			if v.Kind != lens.KindVerification {
				t.Errorf("Google LLC filed under %q, want %q", v.Kind, lens.KindVerification)
			}
		}
	}
	if googles != 1 {
		t.Errorf("Google LLC listed %d time(s), want once: %+v", googles, r.Vendors)
	}
	if got := vendorNames(&r)["Google Workspace"]; got != lens.KindSPF {
		t.Errorf("Google Workspace kind %q, want %q", got, lens.KindSPF)
	}
	if !reflect.DeepEqual(r.UnrecognizedSPF, []string{"spf.acme-mailer.example"}) {
		t.Errorf("unrecognized SPF = %v", r.UnrecognizedSPF)
	}
	if !reflect.DeepEqual(r.UnrecognizedTokens, []string{"acme-domain-verification="}) {
		t.Errorf("unrecognized tokens = %v", r.UnrecognizedTokens)
	}

	text := lens.FormatVendorReport(r)
	for _, want := range []string{"SPF includes no vendor entry recognizes (1): spf.acme-mailer.example",
		"no DNS-SD prefix recognizes (1): acme-domain-verification="} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, lens.KindVerification+":") != 1 {
		t.Errorf("verification kind is not listed once:\n%s", text)
	}
}

// Parties without a stored organization are named sensibly: reverse lookup
// names and private addresses are not vendors, an address in the subject's
// own netblock is controlled, other bare addresses are grouped, and a
// provider's many name server domains are one vendor.
func TestThirdPartyLensNamesUnattributedParties(t *testing.T) {
	g := aitest.VendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	for _, n := range []string{"old.colgate.edu", "legacy.colgate.edu", "ext.colgate.edu",
		"1.1.43.149.in-addr.arpa", "ns-2048.awsdns-64.com", "ns-2051.awsdns-67.co.uk"} {
		add(n, "FQDN", map[string]any{"name": n})
		if strings.HasSuffix(n, ".colgate.edu") {
			link("colgate.edu", "node", n, "SimpleRelation")
		}
	}
	for _, ip := range []string{"10.1.2.3", "149.43.9.9", "203.0.113.5"} {
		add(ip, "IPAddress", map[string]any{"address": ip})
	}

	link("old.colgate.edu", "dns_record", "10.1.2.3", "BasicDNSRelation")
	link("legacy.colgate.edu", "dns_record", "149.43.9.9", "BasicDNSRelation")
	link("ext.colgate.edu", "dns_record", "203.0.113.5", "BasicDNSRelation")
	link("ip-own", "ptr_record", "1.1.43.149.in-addr.arpa", "SimpleRelation")
	link("dr", "name_server", "ns-2048.awsdns-64.com", "SimpleRelation")
	link("dr", "name_server", "ns-2051.awsdns-67.co.uk", "SimpleRelation")

	r, err := lens.SearchThirdParties(context.Background(), g, aitest.VendorCatalog{PlanCatalog: aitest.TestOAMCatalog}, g.Assets["colgate.edu"])
	if err != nil {
		t.Fatal(err)
	}

	got := vendorNames(&r)
	for _, absent := range []string{"10.1.2.3", "149.43.9.9", "203.0.113.5", "in-addr.arpa", "awsdns-64.com",
		"awsdns-67.co.uk"} {
		if _, ok := got[absent]; ok {
			t.Errorf("%s reported as a vendor: %v", absent, got)
		}
	}
	for _, v := range r.Vendors {
		switch v.Vendor {
		case lens.UnattributedAddresses:
			if v.Assets != 1 || v.Examples[0] != "ext.colgate.edu" {
				t.Errorf("unattributed addresses: %+v, want only ext.colgate.edu", v)
			}
		case "Amazon Route 53":
			if v.Assets != 1 {
				t.Errorf("Amazon Route 53 counted %d asset(s), want the one domain record", v.Assets)
			}
		}
	}
	for _, want := range []string{lens.UnattributedAddresses, "Amazon Route 53"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s missing: %v", want, got)
		}
	}
}
