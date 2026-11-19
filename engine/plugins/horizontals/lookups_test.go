// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package horizontals

import (
	"net/netip"
	"sort"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

func labels(ents []*dbt.Entity) string {
	var out []string
	for _, e := range ents {
		out = append(out, e.Asset.Key())
	}

	sort.Strings(out)
	return strings.Join(out, " | ")
}

func link(name string) *general.SimpleRelation { return &general.SimpleRelation{Name: name} }

func TestContactRecordOrganizationsAndLocations(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(1440)
	h := NewHorizontals().(*horizPlugin)

	dr := sess.Asset(t, &oamreg.DomainRecord{Domain: "example.com", Name: "example.com", ID: "D1"})
	cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://rdap.example/domain/example.com"})
	org := sess.Asset(t, &oamorg.Organization{ID: "org-1", Name: "Example Inc"})
	hq := sess.Asset(t, &contact.Location{Address: "1 Main St Springfield IL 62701 US", StreetName: "Main St",
		BuildingNumber: "1", City: "Springfield", Province: "IL", PostalCode: "62701", Country: "US"})
	branch := sess.Asset(t, &contact.Location{Address: "2 Side St Springfield IL 62701 US", StreetName: "Side St",
		BuildingNumber: "2", City: "Springfield", Province: "IL", PostalCode: "62701", Country: "US"})

	sess.Edge(t, dr, link("registrant_contact"), cr)
	sess.Edge(t, cr, link("organization"), org)
	sess.Edge(t, org, link("hq_address"), hq)
	// The same location through both the organization and the record.
	sess.Edge(t, cr, link("location"), hq)
	sess.Edge(t, cr, link("location"), branch)

	got, err := h.getContactRecord(sess, dr, "registrant_contact")
	if err != nil || got.ID != cr.ID {
		t.Fatalf("getContactRecord = %v, %v", got, err)
	}
	if _, err := h.getContactRecord(sess, dr, "technical_contact"); err == nil {
		t.Error("a missing contact record was found")
	}

	orgs, locs := h.lookupContactRecordOrgsAndLocations(sess, cr)
	if labels(orgs) != "org-1" {
		t.Errorf("organizations = %q", labels(orgs))
	}
	if got, want := labels(locs), "1 Main St Springfield IL 62701 US | 2 Side St Springfield IL 62701 US"; got != want {
		t.Errorf("locations = %q, want %q (each once)", got, want)
	}
}

func TestPrivacyProxyOrgSuppressed(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(1440)
	h := NewHorizontals().(*horizPlugin)

	dr := sess.Asset(t, &oamreg.DomainRecord{Domain: "example.com", Name: "example.com", ID: "D1"})
	cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://rdap.example/domain/example.com"})
	real := sess.Asset(t, &oamorg.Organization{ID: "org-1", Name: "Example Inc"})
	proxy := sess.Asset(t, &oamorg.Organization{ID: "org-2", Name: "Domains By Proxy, LLC"})

	sess.Edge(t, dr, link("registrant_contact"), cr)
	sess.Edge(t, cr, link("organization"), real)
	sess.Edge(t, cr, link("organization"), proxy)

	// A privacy-proxy registrant is shared by thousands of unrelated domains, so
	// it must never be returned as a horizontal correlation anchor.
	orgs, _ := h.lookupContactRecordOrgsAndLocations(sess, cr)
	if labels(orgs) != "org-1" {
		t.Errorf("privacy-proxy organization must be suppressed; organizations = %q", labels(orgs))
	}

	if !h.isPrivacyProxyOrg(proxy) {
		t.Error("the proxy organization should be detected as a privacy proxy")
	}
	if h.isPrivacyProxyOrg(real) {
		t.Error("a real organization must not be flagged as a privacy proxy")
	}
}

func TestPTRRecordLookups(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(1440)
	h := &horaddr{name: "Horizontals-IPAddress-Handler", plugin: NewHorizontals().(*horizPlugin)}

	ip := sess.Asset(t, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.5"), Type: "IPv4"})
	ptr := sess.Asset(t, &oamdns.FQDN{Name: "5.2.0.192.in-addr.arpa"})
	host := sess.Asset(t, &oamdns.FQDN{Name: "mail.example.com"})
	sess.Edge(t, ip, link("ptr_record"), ptr)

	if got, err := h.lookupPTRRecordName(sess, ip); err != nil || got.ID != ptr.ID {
		t.Fatalf("lookupPTRRecordName = %v, %v", got, err)
	}
	if _, err := h.lookupPTRRecordData(sess, ptr); err == nil {
		t.Error("PTR data was found before it was stored")
	}

	// Only a PTR record (type 12) is the data; a CNAME is not.
	sess.Edge(t, ptr, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 5, Class: 1}},
		sess.Asset(t, &oamdns.FQDN{Name: "alias.example.net"}))
	if _, err := h.lookupPTRRecordData(sess, ptr); err == nil {
		t.Error("a CNAME was taken for PTR data")
	}

	sess.Edge(t, ptr, &oamdns.BasicDNSRelation{Name: "dns_record", Header: oamdns.RRHeader{RRType: 12, Class: 1}},
		host)
	if got, err := h.lookupPTRRecordData(sess, ptr); err != nil || got.ID != host.ID {
		t.Fatalf("lookupPTRRecordData = %v, %v", got, err)
	}

	// Without the IPAddress to FQDN transformation, nothing is looked up.
	plain := plugintest.NewSession(t)
	if _, err := h.lookupPTRRecordName(plain, ip); err == nil {
		t.Error("a PTR lookup ran without its transformation")
	}
}

func TestInOwnedNetblock(t *testing.T) {
	sess := plugintest.NewSession(t)
	h := &horaddr{name: "Horizontals-IPAddress-Handler", plugin: NewHorizontals().(*horizPlugin)}

	// A netblock in scope is one the organization owns (added by the scored
	// infrastructure correlation, or operator-provided).
	sess.Scope().Add(&oamnet.Netblock{CIDR: netip.MustParsePrefix("192.0.2.0/24"), Type: "IPv4"})

	if cidr, ok := h.inOwnedNetblock(sess, &oamnet.IPAddress{Address: netip.MustParseAddr("192.0.2.5"), Type: "IPv4"}); !ok || cidr != "192.0.2.0/24" {
		t.Errorf("an IP inside an in-scope netblock should be owned; cidr=%q ok=%v", cidr, ok)
	}
	if _, ok := h.inOwnedNetblock(sess, &oamnet.IPAddress{Address: netip.MustParseAddr("198.51.100.5"), Type: "IPv4"}); ok {
		t.Error("an IP outside every in-scope netblock should not be owned")
	}
}

func TestRegisteredDomainAndNetblock(t *testing.T) {
	sess := plugintest.NewSession(t)
	h := NewHorizontals().(*horizPlugin)

	apex := sess.Asset(t, &oamdns.FQDN{Name: "example.com"})
	dr := sess.Asset(t, &oamreg.DomainRecord{Domain: "example.com", Name: "example.com", ID: "D1"})
	if got, err := h.getRegisteredDomainEntity(sess, dr); err != nil || got.ID != apex.ID {
		t.Errorf("getRegisteredDomainEntity = %v, %v", got, err)
	}
	if _, err := h.getRegisteredDomainEntity(sess, apex); err == nil {
		t.Error("an FQDN was taken for a domain record")
	}

	cidr := netip.MustParsePrefix("192.0.2.0/24")
	nb := sess.Asset(t, &oamnet.Netblock{CIDR: cidr, Type: "IPv4"})
	rec := sess.Asset(t, &oamreg.IPNetRecord{CIDR: cidr, Handle: "NET-192-0-2-0-1", Type: "IPv4",
		StartAddress: netip.MustParseAddr("192.0.2.0"), EndAddress: netip.MustParseAddr("192.0.2.255"),
		Name: "TEST-NET-1"})
	if got, err := h.getRegisteredNetblockEntity(sess, rec); err != nil || got.ID != nb.ID {
		t.Errorf("getRegisteredNetblockEntity = %v, %v", got, err)
	}

	other := sess.Asset(t, &oamreg.IPNetRecord{CIDR: netip.MustParsePrefix("198.51.100.0/24"),
		Handle: "NET-198-51-100-0-1", Type: "IPv4", StartAddress: netip.MustParseAddr("198.51.100.0"),
		EndAddress: netip.MustParseAddr("198.51.100.255"), Name: "TEST-NET-2"})
	if _, err := h.getRegisteredNetblockEntity(sess, other); err == nil {
		t.Error("a netblock that was never stored was found")
	}
}
