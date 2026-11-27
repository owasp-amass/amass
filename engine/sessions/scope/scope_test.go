// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"net/netip"
	"testing"

	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

func newScope() *Scope { return New(nil).(*Scope) }

func inScope(s *Scope, a oam.Asset) bool {
	_, conf := s.IsAssetInScope(a, 0)
	return conf > 0
}

func TestDomains(t *testing.T) {
	s := newScope()
	if !s.AddDomain(" Example.COM ") || s.AddDomain("example.com") {
		t.Error("a registered domain was not added once")
	}
	if s.AddDomain("www.example.org") || s.AddDomain("") || s.AddDomain("com") {
		t.Error("a subdomain, an empty name or a public suffix was added")
	}
	if got := s.Domains(); len(got) != 1 || got[0] != "example.com" || len(s.FQDNs()) != 1 {
		t.Errorf("domains = %v", got)
	}

	for name, want := range map[string]bool{
		"example.com": true, "WWW.Example.com": true, "a.b.example.com": true,
		"badexample.com": false, "example.com.evil.net": false, "": false,
	} {
		if got := inScope(s, &oamdns.FQDN{Name: name}); got != want {
			t.Errorf("%q in scope = %v, want %v", name, got, want)
		}
	}
}

func TestAddAndMatchByAssetType(t *testing.T) {
	s := newScope()
	nb := netip.MustParsePrefix("198.51.100.0/24")

	added := map[string]oam.Asset{
		"email domain":   &oamgen.Identifier{UniqueID: "email:a@example.com", ID: "a@example.com", Type: oamgen.EmailAddress},
		"ip address":     &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.10"), Type: "IPv4"},
		"netblock":       &oamnet.Netblock{CIDR: nb, Type: "IPv4"},
		"asn":            &oamnet.AutonomousSystem{Number: 64496},
		"domain record":  &oamreg.DomainRecord{Domain: "example.org"},
		"ipnet record":   &oamreg.IPNetRecord{CIDR: netip.MustParsePrefix("203.0.113.0/24"), Type: "IPv4"},
		"autnum record":  &oamreg.AutnumRecord{Number: 64497},
		"certificate":    &oamcert.TLSCertificate{SubjectCommonName: "example.net"},
		"url host":       &oamurl.URL{Raw: "https://example.io/", Host: "example.io"},
		"url address":    &oamurl.URL{Raw: "https://192.0.2.20/", Host: "192.0.2.20"},
		"organization":   &oamorg.Organization{ID: "acme:1", Name: "Acme, Inc."},
		"street address": &oamcon.StreetAddress{Address: "1 Main St, Springfield, IL 62701", BuildingNumber: "1", StreetName: "Main St", City: "Springfield", Province: "IL", PostalCode: "62701"},
	}
	for name, a := range added {
		if !s.Add(a) {
			t.Errorf("%s was not added", name)
		}
		if s.Add(a) {
			t.Errorf("%s was added twice", name)
		}
	}
	if s.Add(&oamgen.Identifier{UniqueID: "duns:1", ID: "1", Type: "duns"}) {
		t.Error("an identifier that is not an email address was added")
	}

	for name, c := range map[string]struct {
		asset oam.Asset
		want  bool
	}{
		"email at a scope domain":     {&oamgen.Identifier{ID: "b@mail.example.com", Type: oamgen.EmailAddress}, true},
		"email elsewhere":             {&oamgen.Identifier{ID: "b@other.com", Type: oamgen.EmailAddress}, false},
		"address in a netblock":       {&oamnet.IPAddress{Address: netip.MustParseAddr("198.51.100.7"), Type: "IPv4"}, true},
		"listed address":              {&oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.10"), Type: "IPv4"}, true},
		"other address":               {&oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.11"), Type: "IPv4"}, false},
		"same netblock":               {&oamnet.Netblock{CIDR: nb, Type: "IPv4"}, true},
		"netblock inside a scope one": {&oamnet.Netblock{CIDR: netip.MustParsePrefix("198.51.100.128/25"), Type: "IPv4"}, true},
		"wider netblock":              {&oamnet.Netblock{CIDR: netip.MustParsePrefix("198.51.0.0/16"), Type: "IPv4"}, false},
		"asn":                         {&oamnet.AutonomousSystem{Number: 64497}, true},
		"other asn":                   {&oamnet.AutonomousSystem{Number: 1}, false},
		"certificate":                 {&oamcert.TLSCertificate{SubjectCommonName: "www.example.net"}, true},
		"url":                         {&oamurl.URL{Host: "shop.example.io"}, true},
		"organization, other form":    {&oamorg.Organization{Name: "ACME INC"}, true},
		"organization misspelt":       {&oamorg.Organization{Name: "Acmee Inc"}, true},
		"organization containing it":  {&oamorg.Organization{Name: "Acme Hospitality REIT"}, false},
		"registrant of a record":      {&oamreg.DomainRecord{Domain: "unrelated.com", Name: "Acme Inc"}, true},
		"same address":                {&oamcon.StreetAddress{BuildingNumber: "1", StreetName: "Main St", City: "Springfield", Province: "IL"}, true},
		"address written otherwise":   {&oamcon.StreetAddress{Address: "1 Main Street, Suite 200, Springfield, IL 62701", BuildingNumber: "1", StreetName: "Main Street", City: "Springfield", Province: "Illinois", PostalCode: "62701"}, true},
		"other address on the street": {&oamcon.StreetAddress{BuildingNumber: "2", StreetName: "Main St", City: "Springfield", Province: "IL"}, false},
	} {
		if got := inScope(s, c.asset); got != c.want {
			t.Errorf("%s: in scope = %v, want %v", name, got, c.want)
		}
	}

	// a near match is not good enough when the caller asks for more
	if _, conf := s.IsAssetInScope(&oamorg.Organization{Name: "Acmee Inc"}, 95); conf >= 95 {
		t.Errorf("a misspelling met a confidence of 95: %d", conf)
	}
	if _, conf := s.IsAssetInScope(&oamorg.Organization{Name: "Acme Corporation"}, 100); conf != 100 {
		t.Errorf("the same organization in another form = %d, want 100", conf)
	}
}

func TestOrganizations(t *testing.T) {
	s := newScope()
	o := &oamorg.Organization{ID: "acme:1", Name: "Acme", LegalName: "Acme Corporation"}
	if !s.AddOrganization(o) || s.AddOrganization(&oamorg.Organization{ID: "acme:2", Name: "ACME, Inc."}) {
		t.Error("the organization was not added once by its name key")
	}
	if !s.AddOrgByName("Globex") || len(s.Organizations()) != 2 {
		t.Errorf("organizations = %v", s.Organizations())
	}
	if s.AddOrganization(&oamorg.Organization{ID: "x"}) {
		t.Error("an organization without a name was added")
	}
}

func TestBlacklistedNamesAreOutOfScope(t *testing.T) {
	s := newScope()
	s.AddDomain("example.com")
	s.AddBlacklist("internal.example.com")
	if inScope(s, &oamdns.FQDN{Name: "a.internal.example.com"}) || inScope(s, &oamurl.URL{Host: "internal.example.com"}) {
		t.Error("a blacklisted name is in scope")
	}
	if !inScope(s, &oamdns.FQDN{Name: "www.example.com"}) {
		t.Error("a name beside the blacklisted one is out of scope")
	}
}

func TestOrgNameSimilarToCommon(t *testing.T) {
	s := newScope()
	for _, c := range []struct {
		org, cn string
		want    bool
	}{
		{"OWASP Foundation", "www.owasp.org", true},
		{"Open Worldwide Application Security Project", "owasp.org", true},
		{"Google LLC", "www.google.com", true},
		{"Acme Corp", "co.uk", false},
		{"Acme Corp", "www.co-op.example", false},
		{"OWASP Foundation", "www.utica.edu", false},
		{"OWASP Foundation", "not a name", false},
	} {
		got := s.orgNameSimilarToCommon(&oamorg.Organization{Name: c.org}, &oamcert.TLSCertificate{SubjectCommonName: c.cn})
		if got != c.want {
			t.Errorf("orgNameSimilarToCommon(%q, %q) = %v, want %v", c.org, c.cn, got, c.want)
		}
	}
}
