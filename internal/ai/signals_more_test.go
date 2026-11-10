// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"slices"
	"testing"
)

// moreSignalsFixture adds evidence for the supporting, tiebreaker and
// negative signals to signalsFixture:
//   - 203.0.113.5's reverse DNS is portal.colgate.edu, and alumni-mail.net
//     resolves to it;
//   - redirect.example's web service redirects to www.colgate.edu, and
//     elsewhere.example's redirects to notcolgate.edu;
//   - colgate.org (Colgate's) and team-site.org use the same two provider
//     name servers; solo-site.org uses only one of them;
//   - jarm-twin.example's service has the JARM of www.colgate.edu's.
func moreSignalsFixture() valueGraph {
	g := signalsFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }
	link := func(from, label, to, rt string) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	registered := func(domain string) {
		named(domain, "FQDN", domain)
		add("dr-"+domain, "DomainRecord", domain, map[string]any{"domain": domain})
		add("cr-"+domain, "ContactRecord", "https://rdap.example/"+domain, nil)
		link(domain, "registration", "dr-"+domain, "SimpleRelation")
		link("dr-"+domain, "registrant_contact", "cr-"+domain, "SimpleRelation")
	}
	service := func(id string, attrs map[string]any) {
		add(id, "Service", id, map[string]any{"unique_id": id, "service_type": "web-service", "attributes": attrs})
	}

	add("ip-ptr", "IPAddress", "203.0.113.5", map[string]any{"address": "203.0.113.5"})
	link("ip-ptr", "ptr_record", "portal.colgate.edu", "SimpleRelation")
	registered("alumni-mail.net")
	link("alumni-mail.net", "dns_record", "ip-ptr", "BasicDNSRelation")

	registered("redirect.example")
	service("svc-redirect", map[string]any{"Location": []any{"https://www.colgate.edu/welcome"}})
	link("redirect.example", "port", "svc-redirect", "PortRelation")
	registered("elsewhere.example")
	service("svc-elsewhere", map[string]any{"Location": []any{"https://notcolgate.edu/colgate.edu"}})
	link("elsewhere.example", "port", "svc-elsewhere", "PortRelation")

	named("colgate.org", "FQDN", "colgate.org")
	add("dr-colgate.org", "DomainRecord", "colgate.org", map[string]any{"domain": "colgate.org"})
	link("colgate.org", "registration", "dr-colgate.org", "SimpleRelation")
	link("dr-colgate.org", "registrant_contact", "cr-colgate", "SimpleRelation")
	for _, ns := range []string{"ada.ns.dnshost.example", "bob.ns.dnshost.example"} {
		named(ns, "FQDN", ns)
		link("dr-colgate.org", "name_server", ns, "SimpleRelation")
	}
	registered("team-site.org")
	link("dr-team-site.org", "name_server", "ada.ns.dnshost.example", "SimpleRelation")
	link("dr-team-site.org", "name_server", "bob.ns.dnshost.example", "SimpleRelation")
	registered("solo-site.org")
	link("dr-solo-site.org", "name_server", "ada.ns.dnshost.example", "SimpleRelation")

	jarm := Evidence{Kind: "SimpleProperty", Property: map[string]any{"property_name": "JARM",
		"property_value": "2ad2ad0002ad2ad0042d42d000000ad"}}
	service("svc-www", nil)
	link("www.colgate.edu", "port", "svc-www", "PortRelation")
	g.evidence["svc-www"] = []Evidence{jarm}
	registered("jarm-twin.example")
	service("svc-twin", nil)
	link("jarm-twin.example", "port", "svc-twin", "PortRelation")
	g.evidence["svc-twin"] = []Evidence{jarm}
	return g
}

func TestReverseDNSInTheNamespace(t *testing.T) {
	r := signalsReport(t, moreSignalsFixture())
	for _, id := range []string{"ip-ptr", "alumni-mail.net"} {
		c := candidateByID(r, id)
		if c == nil || !slices.Equal(signalIDs(c), []string{"reverse_dns_in_namespace"}) || c.Decision != GapWeak {
			t.Errorf("%s = %+v", id, c)
		}
	}
}

func TestRedirectIntoTheNamespace(t *testing.T) {
	r := signalsReport(t, moreSignalsFixture())
	c := candidateByID(r, "redirect.example")
	if c == nil || !slices.Equal(signalIDs(c), []string{"web_redirect_to_organization"}) {
		t.Fatalf("redirect.example = %+v", c)
	}
	if c.Signals[0].Via != "Service location FQDN" {
		t.Errorf("via = %q", c.Signals[0].Via)
	}
	if c := candidateByID(r, "elsewhere.example"); c != nil {
		t.Errorf("a redirect to a look-alike host counted: %+v", c)
	}
}

func TestSameNameServerSet(t *testing.T) {
	r := signalsReport(t, moreSignalsFixture())
	c := candidateByID(r, "dr-team-site.org")
	if c == nil || !slices.Equal(signalIDs(c), []string{"shared_nameserver_set"}) {
		t.Fatalf("team-site.org registration = %+v", c)
	}
	if c := candidateByID(r, "dr-solo-site.org"); c != nil {
		t.Errorf("a registration sharing one of two name servers counted: %+v", c)
	}
}

func TestJARMIsATiebreaker(t *testing.T) {
	r := signalsReport(t, moreSignalsFixture())
	c := candidateByID(r, "jarm-twin.example")
	if c == nil || !slices.Equal(signalIDs(c), []string{"tls_fingerprint_match"}) || c.Decision != GapWeak {
		t.Fatalf("jarm-twin.example = %+v", c)
	}

	// A tiebreaker beside one strong signal still only needs review.
	if _, d := scoreGap([]GapSignal{{Signal: "certificate_key_reuse"}, {Signal: "tls_fingerprint_match"}},
		true); d != GapReview {
		t.Errorf("strong + tiebreaker = %s", d)
	}
	if _, d := scoreGap([]GapSignal{{Signal: "certificate_key_reuse"}, {Signal: "hosting_in_footprint"}},
		true); d != GapPropose {
		t.Errorf("strong + supporting = %s", d)
	}
}

func TestParkedPagesBlockProposals(t *testing.T) {
	g := moreSignalsFixture()
	g.assets["svc-park"] = Asset{ID: "svc-park", Type: "Service", Key: "svc-park", Content: map[string]any{
		"unique_id": "svc-park", "output": "<html><h1>This domain may be for sale!</h1></html>"}}
	g.links = append(g.links, Relation{ID: "arts-port", FromID: "colgate-arts.org", ToID: "svc-park", Label: "port",
		Type: "PortRelation"})

	c := candidateByID(signalsReport(t, g), "colgate-arts.org")
	if c == nil || !slices.Contains(signalIDs(c), "parked_for_sale") || c.Decision != GapReview {
		t.Errorf("a parked candidate = %+v", c)
	}
}

func TestNameTokensAreDistinctive(t *testing.T) {
	def, _ := firstSignal(matchNameToken)
	if got := nameTokens("Colgate University", def.Params); !slices.Equal(got, []string{"colgate"}) {
		t.Errorf("tokens = %v", got)
	}
	if got := nameTokens("The OWASP Foundation, Inc.", def.Params); !slices.Equal(got, []string{"owasp"}) {
		t.Errorf("tokens = %v (foundation is generic)", got)
	}
	if got := nameTokens("Acme Holdings Group", def.Params); len(got) != 0 {
		t.Errorf("tokens = %v (acme is too short, the rest are generic)", got)
	}
}

func TestRedirectHost(t *testing.T) {
	cases := map[[2]string]string{
		{"location", "https://www.colgate.edu/x"}:     "www.colgate.edu",
		{"location", "/relative/path"}:                "",
		{"refresh", "0; url=https://colgate.edu/"}:    "colgate.edu",
		{"refresh", "5;URL='http://www.colgate.edu'"}: "www.colgate.edu",
		{"refresh", "10"}:                             "",
	}
	for in, want := range cases {
		if got := redirectHost(in[0], in[1]); got != want {
			t.Errorf("redirectHost(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
