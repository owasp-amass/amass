// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope_test

import (
	"net/netip"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamplat "github.com/owasp-amass/open-asset-model/platform"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func port() *oamgen.PortRelation {
	return &oamgen.PortRelation{Name: "port", PortNumber: 443, Protocol: "tcp"}
}

// Assets the scope cannot judge take the standing of what they hang off.
func TestStandingIsInherited(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddDomain("example.com")
	sc := sess.Scope()

	www := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	svc := sess.Asset(t, &oamplat.Service{ID: "svc-1", Type: "HTTP"})
	sess.Edge(t, www, port(), svc)
	if got := sc.StandingOf(svc); got != et.InScope {
		t.Errorf("a service on an in-scope name: %s", got)
	}

	// a phone on the registrant contact of an in-scope domain, two steps up
	dr := sess.Asset(t, &oamreg.DomainRecord{Domain: "example.com", Name: "example.com", ID: "D-1"})
	cr := sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/domain/example.com"})
	ph := sess.Asset(t, &oamcon.Phone{Raw: "+13155550100", E164: "+13155550100"})
	sess.Edge(t, dr, &oamgen.SimpleRelation{Name: "registrant_contact"}, cr)
	sess.Edge(t, cr, &oamgen.SimpleRelation{Name: "phone"}, ph)
	if got := sc.StandingOf(ph); got != et.InScope {
		t.Errorf("a registrant's phone: %s", got)
	}

	other := sess.Asset(t, &oamdns.FQDN{Name: "www.other.org"})
	osvc := sess.Asset(t, &oamplat.Service{ID: "svc-2", Type: "HTTP"})
	sess.Edge(t, other, port(), osvc)
	if got := sc.StandingOf(osvc); got != et.Unconsidered {
		t.Errorf("a service on an outside name: %s", got)
	}

	prod := sess.Asset(t, &oamplat.Product{ID: "nginx", Name: "nginx", Type: "Web Server"})
	if got := sc.StandingOf(prod); got != et.NotGoverned {
		t.Errorf("a type with no standing rules: %s", got)
	}
}

func TestConnectedWithin(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddCIDR("192.0.2.0/24")
	sc := sess.Scope()

	name := sess.Asset(t, &oamdns.FQDN{Name: "mail.other.org"})
	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.10"), Type: "IPv4"})
	sess.Edge(t, name, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 1, Class: 1}}, ip)

	if sc.StandingOf(name) != et.Unconsidered {
		t.Fatal("the name is outside the scope")
	}
	if !sc.ConnectedWithin(name, 1) {
		t.Error("a name resolving to an in-scope address is connected within one hop")
	}
	lone := sess.Asset(t, &oamdns.FQDN{Name: "lone.other.org"})
	if sc.ConnectedWithin(lone, 2) {
		t.Error("an unlinked name is not connected")
	}
}

// A held asset is queued again once an admission takes it in.
func TestHeldAssetsAreReleased(t *testing.T) {
	sess := plugintest.NewSession(t)
	sc := sess.Scope().(*scope.Scope)
	sc.SetAdmissionDeciders(&decider{outcome: et.Admitted})

	www := sess.Asset(t, &oamdns.FQDN{Name: "www.related.org"})
	svc := sess.Asset(t, &oamplat.Service{ID: "svc-3", Type: "HTTP"})
	sess.Edge(t, www, port(), svc)
	if scope.InFootprint(sc.StandingOf(svc)) {
		t.Fatal("the service is outside the scope before the admission")
	}
	sc.Hold(svc)

	if d, _ := sc.Admit(request(t, sess, "related.org", "shared-registrant-org")); d.Outcome != et.Admitted {
		t.Fatalf("admission = %+v", d)
	}
	waitFor(t, func() bool { return sess.Backlog().Has(svc) })
	if got := sc.StandingOf(svc); got != et.StandingAdmitted {
		t.Errorf("the service's standing after the admission: %s", got)
	}
}

func dnsRecord(rrtype int) *oamdns.BasicDNSRelation {
	return &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: rrtype, Class: 1}}
}

// An address takes the standing of an in-scope name with an alias to the
// name that resolves to it; the provider's name between them takes none.
func TestAliasesPassStandingToAddresses(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddDomain("example.com")
	sc := sess.Scope()

	www := sess.Asset(t, &oamdns.FQDN{Name: "www.example.com"})
	edge := sess.Asset(t, &oamdns.FQDN{Name: "example.cdn.example.net"})
	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("198.51.100.7"), Type: "IPv4"})
	sess.Edge(t, www, dnsRecord(5), edge)
	sess.Edge(t, edge, dnsRecord(1), ip)

	if got := sc.StandingOf(ip); got != et.InScope {
		t.Errorf("an address behind an in-scope name's alias: %s", got)
	}
	if got := sc.StandingOf(edge); got != et.Unconsidered {
		t.Errorf("the provider's name between them: %s", got)
	}
}

// Phones and street addresses take the standing of whoever holds them: the
// target's registrant, an organization in scope, or the session's seeds, but
// not a registrar or a network operator.
func TestContactsTakeTheirHoldersStanding(t *testing.T) {
	setup := func(vendorInScope bool) (*plugintest.Session, map[string]*dbt.Entity) {
		sess := plugintest.NewSession(t)
		sess.Scope().AddDomain("sunyit.edu")
		a := map[string]*dbt.Entity{}
		rel := func(from string, label string, to string) {
			sess.Edge(t, a[from], &oamgen.SimpleRelation{Name: label}, a[to])
		}

		a["record"] = sess.Asset(t, &oamreg.DomainRecord{Domain: "sunyit.edu", Name: "sunyit.edu"})
		a["registrant"] = sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/domain/sunyit.edu"})
		a["home"] = sess.Asset(t, &oamcon.StreetAddress{Address: "100 Seymour Road Utica NY 13502 US",
			BuildingNumber: "100", StreetName: "Seymour Road", City: "Utica", Country: "US"})
		rel("record", "registrant_contact", "registrant")
		rel("registrant", "street_address", "home")

		// a network operator's details, from the registration record of a
		// netblock the target's names point into
		a["netrec"] = sess.Asset(t, &oamreg.IPNetRecord{CIDR: netip.MustParsePrefix("20.0.0.0/11"),
			Handle: "NET-20-0-0-0-1", StartAddress: netip.MustParseAddr("20.0.0.0"),
			EndAddress: netip.MustParseAddr("20.31.255.255"), Type: "IPv4", Name: "MSFT"})
		a["operator"] = sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/entity/MSFT"})
		a["vendor"] = sess.Asset(t, &oamorg.Organization{ID: "msft:test", Name: "microsoft corporation"})
		a["away"] = sess.Asset(t, &oamcon.StreetAddress{Address: "1 Microsoft Way Redmond WA 98052 US",
			BuildingNumber: "1", StreetName: "Microsoft Way", City: "Redmond", Country: "US"})
		rel("netrec", "registrant", "operator")
		rel("operator", "organization", "vendor")
		rel("operator", "street_address", "away")
		if vendorInScope {
			sess.Scope().Add(a["vendor"].Asset)
		}

		// the registrar of the target's domain
		a["registrar"] = sess.Asset(t, &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/registrar/1"})
		a["desk"] = sess.Asset(t, &oamcon.StreetAddress{Address: "100 Registrar Lane Reston VA 20190 US",
			BuildingNumber: "100", StreetName: "Registrar Lane", City: "Reston", Country: "US"})
		rel("record", "registrar_contact", "registrar")
		rel("registrar", "street_address", "desk")

		a["phone"] = sess.Asset(t, &oamcon.Phone{Raw: "+1 (607) 274-3011", E164: "+16072743011"})
		return sess, a
	}

	sess, a := setup(false)
	sc := sess.Scope()
	for name, want := range map[string]et.Standing{"home": et.InScope, "away": et.Unconsidered,
		"desk": et.Unconsidered, "phone": et.Unconsidered} {
		if got := sc.StandingOf(a[name]); got != want {
			t.Errorf("%s: %s, want %s", name, got, want)
		}
	}

	// the address of an organization in scope, and a seed phone
	sess, a = setup(true)
	sess.Config().AddPhone("+1 607 274 3011")
	for _, name := range []string{"away", "phone"} {
		if got := sess.Scope().StandingOf(a[name]); got != et.InScope {
			t.Errorf("%s: %s, want in scope", name, got)
		}
	}
}
