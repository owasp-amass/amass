// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
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
			"include:spf.acme-mailer.example include:service-now.com include:e2ma.net " +
			"redirect=_spf.mailgun.org -all",
		"some unrelated note mentioning sendgrid.net",
	}

	scan := scanTXT(records, "colgate.edu")
	var senders []string
	for _, v := range scan.senders {
		if v.Kind != KindSPF {
			t.Errorf("%s: kind %q, want %q", v.Vendor, v.Kind, KindSPF)
		}
		senders = append(senders, v.Vendor)
	}

	// The vendor's own domain (service-now.com, e2ma.net) names it as well
	// as the documented include does.
	want := []string{"Emma", "Google Workspace", "Mailgun", "Microsoft 365", "Mimecast", "ServiceNow",
		"Twilio SendGrid"}
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

// A provider reached once through its organization and once only through
// its domain is one vendor, named by the organization.
func TestVendorSetMergesDomainAndOrganization(t *testing.T) {
	v := vendorSet{}
	kind := "DNS: FQDNs"
	asset := func(name string) graph.Asset {
		return graph.Asset{ID: name, Type: "FQDN", Content: map[string]any{"name": name}}
	}

	v.add("dnsmadeeasy.com", "", kind, "FQDN dns_record", asset("a.example.edu"), nil)
	v.add("dnsmadeeasy", "org-1", kind, "FQDN dns_record", asset("b.example.edu"), nil)
	v.add("dnsmadeeasy.com", "", kind, "FQDN dns_record", asset("a.example.edu"), nil)
	v.add("DNS Made Easy, LLC", "org-1", kind, "FQDN dns_record", asset("c.example.edu"), nil)
	v.add("google.com", "", kind, "FQDN dns_record", asset("a.example.edu"), nil)
	for i := 0; i < 5; i++ {
		v.add("google", "org-2", kind, "FQDN dns_record", asset(fmt.Sprintf("h%d.example.edu", i)), nil)
	}
	v.add("google", "org-2", kind, "FQDN dns_record", asset("h4.example.edu"), nil)

	if len(v) != 2 {
		t.Fatalf("got %d vendors, want 2: %+v", len(v), v)
	}
	for _, use := range v {
		switch use.VendorID {
		case "org-1":
			if use.Vendor != "DNS Made Easy, LLC" && use.Vendor != "dnsmadeeasy" {
				t.Errorf("DNS Made Easy named %q", use.Vendor)
			}
			if use.Assets != 3 {
				t.Errorf("DNS Made Easy counted %d assets, want 3", use.Assets)
			}
		case "org-2":
			// Counted once each, even past the examples kept.
			if use.Vendor != "google" || use.Assets != 6 {
				t.Errorf("Google: %q with %d assets, want google with 6", use.Vendor, use.Assets)
			}
		default:
			t.Errorf("vendor %q kept its domain name", use.Vendor)
		}
	}
}

func TestPartyKey(t *testing.T) {
	for name, want := range map[string]string{"dnsmadeeasy.com": "dnsmadeeasy", "DNSMadeEasy": "dnsmadeeasy",
		"Fastly, Inc.": "fastly", "awsdns-67.co.uk": "awsdns67", "Let's Encrypt": "letsencrypt", "...": "..."} {
		if got := partyKey(name); got != want {
			t.Errorf("partyKey(%q) = %q, want %q", name, got, want)
		}
	}
}

func TestNamedOrganizationSkipsPlaceholders(t *testing.T) {
	org := func(id, name string) graph.Asset {
		return graph.Asset{ID: id, Type: "Organization", Content: map[string]any{"name": name}}
	}

	if got, ok := namedOrganization([]graph.Asset{org("1", "domain admin"), org("2", "Ithaka Harbors")}); !ok ||
		got.ID != "2" {
		t.Errorf("got %+v, want Ithaka Harbors", got)
	}
	if _, ok := namedOrganization([]graph.Asset{org("1", "Domain Admin")}); ok {
		t.Error("a placeholder organization named the party")
	}
}

func TestSPFMacroFree(t *testing.T) {
	for in, want := range map[string]string{
		"%{ir}.%{v}.%{d}.spf.has.pphosted.com": "spf.has.pphosted.com",
		"_spf.google.com":                      "_spf.google.com",
		"%{d}":                                 "",
	} {
		if got := spfMacroFree(in); got != want {
			t.Errorf("spfMacroFree(%q) = %q, want %q", in, got, want)
		}
	}

	scan := scanTXT([]string{"v=spf1 include:%{ir}.%{v}.%{d}.spf.has.example.net -all"}, "example.org")
	if !reflect.DeepEqual(scan.unknownSPF, []string{"spf.has.example.net"}) {
		t.Errorf("macro include reported as %v", scan.unknownSPF)
	}
}
