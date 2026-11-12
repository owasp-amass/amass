// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"reflect"
	"strings"
	"testing"
)

func TestTXTVendorCatalogCitesSources(t *testing.T) {
	rules := loadTXTVendors()
	if len(rules.SPFSenders) == 0 {
		t.Fatal("no SPF senders loaded")
	}
	for _, s := range rules.SPFSenders {
		if !strings.HasPrefix(s.Source, "https://") {
			t.Errorf("%s has no documentation source", s.Vendor)
		}
	}
	if err := validateTXTVendors(txtVendorRules{VerificationMarkers: []string{"verification"},
		SPFSenders: []spfSender{{Vendor: "Example", Domains: []string{"spf.example.com"}}}}); err == nil {
		t.Error("a sender without a source was accepted")
	}
}

func TestScanTXT(t *testing.T) {
	records := []string{
		"google-site-verification=abc123",
		"acme-domain-verification=xyz",
		"MS=ms12345678",
		"v=spf1 ip4:149.43.0.0/16 include:_spf.google.com include:spf.protection.outlook.com " +
			"include:u123.wl.sendgrid.net include:_spf.colgate.edu ~include:us._netblocks.mimecast.com " +
			"include:spf.acme-mailer.example redirect=_spf.mailgun.org -all",
		"some unrelated note mentioning sendgrid.net",
	}

	scan := scanTXT(records, "colgate.edu")
	var senders []string
	for _, v := range scan.senders {
		if v.Kind != kindSPF {
			t.Errorf("%s: kind %q, want %q", v.Vendor, v.Kind, kindSPF)
		}
		senders = append(senders, v.Vendor)
	}

	want := []string{"Google Workspace", "Mailgun", "Microsoft 365", "Mimecast", "Twilio SendGrid"}
	if !reflect.DeepEqual(senders, want) {
		t.Errorf("senders = %v, want %v", senders, want)
	}
	// The domain's own include is not a vendor, recognized or not.
	if !reflect.DeepEqual(scan.unknownSPF, []string{"spf.acme-mailer.example"}) {
		t.Errorf("unknown SPF = %v, want only spf.acme-mailer.example", scan.unknownSPF)
	}
	if !reflect.DeepEqual(scan.tokens, records[:2]) {
		t.Errorf("verification-like records = %v, want %v", scan.tokens, records[:2])
	}
}

func TestFindVendorsReportsVerificationsAndUnrecognizedRecords(t *testing.T) {
	g := vendorFixture()
	g.assets["google"] = Asset{ID: "google", Type: "Organization", Key: "Google LLC",
		Content: map[string]any{"name": "Google LLC"}}
	g.links = append(g.links, Relation{ID: "colgate.edu-verified_for-google", FromID: "colgate.edu", ToID: "google",
		Label: verifiedForLabel, Type: "SimpleRelation"})
	txt := func(id, data string) Evidence {
		return Evidence{ID: id, SubjectID: "colgate.edu", Kind: "property", Property: map[string]any{
			"property_name": dnsRecordProperty, "header": map[string]any{"rr_type": rrTypeTXT}, "data": data}}
	}
	g.evidence = map[string][]Evidence{"colgate.edu": {
		txt("t1", "google-site-verification=abc123"),
		txt("t2", "acme-domain-verification=xyz"),
		txt("t3", "v=spf1 include:_spf.google.com include:spf.acme-mailer.example -all"),
	}}

	known := func(r string) bool { return strings.HasPrefix(r, "google-site-verification=") }
	r, err := FindVendors(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"],
		VendorOptions{KnownVerification: known})
	if err != nil {
		t.Fatal(err)
	}

	googles := 0
	for _, v := range r.Vendors {
		if v.Vendor == "Google LLC" {
			googles++
			if v.Kind != kindVerification {
				t.Errorf("Google LLC filed under %q, want %q", v.Kind, kindVerification)
			}
		}
	}
	if googles != 1 {
		t.Errorf("Google LLC listed %d time(s), want once: %+v", googles, r.Vendors)
	}
	if got := vendorNames(&r)["Google Workspace"]; got != kindSPF {
		t.Errorf("Google Workspace kind %q, want %q", got, kindSPF)
	}
	if !reflect.DeepEqual(r.UnrecognizedSPF, []string{"spf.acme-mailer.example"}) {
		t.Errorf("unrecognized SPF = %v", r.UnrecognizedSPF)
	}
	if !reflect.DeepEqual(r.UnrecognizedTokens, []string{"acme-domain-verification="}) {
		t.Errorf("unrecognized tokens = %v", r.UnrecognizedTokens)
	}

	text := FormatVendorReport(r)
	for _, want := range []string{"SPF includes no vendor entry recognizes (1): spf.acme-mailer.example",
		"no DNS-SD prefix recognizes (1): acme-domain-verification="} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if strings.Count(text, kindVerification+":") != 1 {
		t.Errorf("verification kind is not listed once:\n%s", text)
	}
}

// Parties without a stored organization are named sensibly: reverse lookup
// names and private addresses are not vendors, an address in the subject's
// own netblock is controlled, other bare addresses are grouped, and a
// provider's many name server domains are one vendor.
func TestThirdPartyLensNamesUnattributedParties(t *testing.T) {
	g := vendorFixture()
	add := func(id, typ string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
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

	r, err := searchThirdParties(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate.edu"])
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
		case unattributedAddresses:
			if v.Assets != 1 || v.Examples[0] != "ext.colgate.edu" {
				t.Errorf("unattributed addresses: %+v, want only ext.colgate.edu", v)
			}
		case "Amazon Route 53":
			if v.Assets != 1 {
				t.Errorf("Amazon Route 53 counted %d asset(s), want the one domain record", v.Assets)
			}
		}
	}
	for _, want := range []string{unattributedAddresses, "Amazon Route 53"} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s missing: %v", want, got)
		}
	}
}

func TestVendorNameCatalog(t *testing.T) {
	if !reverseZone("in-addr.arpa") || !reverseZone("ip6.arpa") || reverseZone("arpa.example") {
		t.Error("reverse zones misjudged")
	}
	for domain, want := range map[string]string{"awsdns-64.com": "Amazon Route 53",
		"awsdns-67.co.uk": "Amazon Route 53", "awsdns.com": "awsdns.com", "ultradns.net": "ultradns.net"} {
		if got := vendorNameOf(domain); got != want {
			t.Errorf("vendorNameOf(%s) = %q, want %q", domain, got, want)
		}
	}
}
