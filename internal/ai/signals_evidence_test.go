// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"slices"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// evidenceGraph adds assets and relations to the signals fixture.
type evidenceGraph struct{ valueGraph }

func newEvidenceGraph() evidenceGraph { return evidenceGraph{signalsFixture()} }

func (g evidenceGraph) add(id, typ, key string, content map[string]any) {
	g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
}

func (g evidenceGraph) fqdn(name string) { g.add(name, "FQDN", name, map[string]any{"name": name}) }

func (g *evidenceGraph) link(from, label, to, rt string) string {
	id := from + "-" + label + "-" + to
	g.Links = append(g.Links, graph.Relation{ID: id, FromID: from, ToID: to, Label: label, Type: rt})
	return id
}

// registered adds a registered domain with its registration and registrant
// contact record.
func (g *evidenceGraph) registered(domain string) {
	g.fqdn(domain)
	g.add("dr-"+domain, "DomainRecord", domain, map[string]any{"domain": domain})
	g.add("cr-"+domain, "ContactRecord", "https://rdap.example/"+domain, nil)
	g.link(domain, "registration", "dr-"+domain, "SimpleRelation")
	g.link("dr-"+domain, "registrant_contact", "cr-"+domain, "SimpleRelation")
}

func hasSignal(r lens.OwnershipGapReport, id, signal string) bool {
	c := candidateByID(r, id)
	return c != nil && slices.Contains(signalIDs(c), signal)
}

func TestCAAAccountBinding(t *testing.T) {
	g := newEvidenceGraph()
	acct := `0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/111"`
	g.EvidenceByID["owasp.org"] = append(g.EvidenceByID["owasp.org"], graphtest.CAARecord(acct))

	g.registered("owasp-mail.net")
	g.EvidenceByID["owasp-mail.net"] = []graph.Evidence{graphtest.CAARecord(acct)}

	// a longer account number that starts with OWASP's is another account
	g.registered("other-account.example")
	g.EvidenceByID["other-account.example"] = []graph.Evidence{graphtest.CAARecord(
		`0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/1111"`)}

	r := signalsReport(t, g)
	if !hasSignal(r, "owasp-mail.net", "caa-account-binding") {
		t.Errorf("owasp-mail.net = %+v", candidateByID(r, "owasp-mail.net"))
	}
	if hasSignal(r, "other-account.example", "caa-account-binding") {
		t.Error("an account URI that only starts with OWASP's counted")
	}
}

func TestSharedPrivateAddresses(t *testing.T) {
	g := newEvidenceGraph()
	ip := func(id, addr string) { g.add(id, "IPAddress", addr, map[string]any{"address": addr}) }
	ip("ip-p1", "10.20.30.40")
	ip("ip-p2", "10.20.30.41")
	ip("ip-gw", "10.9.9.1")
	g.link("portal.owasp.org", "dns_record", "ip-p1", "BasicDNSRelation")
	g.link("ns1.owasp.org", "dns_record", "ip-p2", "BasicDNSRelation")
	g.link("ns1.owasp.org", "dns_record", "ip-gw", "BasicDNSRelation")

	// two of OWASP's internal addresses published under another domain
	g.registered("owasp-it.net")
	for name, addr := range map[string]string{"a.owasp-it.net": "ip-p1", "b.owasp-it.net": "ip-p2"} {
		g.fqdn(name)
		g.link("owasp-it.net", "node", name, "SimpleRelation")
		g.link(name, "dns_record", addr, "BasicDNSRelation")
	}
	// one shared address, and a gateway address everyone uses
	g.fqdn("single.example")
	g.link("single.example", "dns_record", "ip-p1", "BasicDNSRelation")
	g.fqdn("router.example")
	g.link("router.example", "dns_record", "ip-gw", "BasicDNSRelation")
	g.fqdn("gw2.example")
	g.link("gw2.example", "dns_record", "ip-gw", "BasicDNSRelation")

	r := signalsReport(t, g)
	for _, name := range []string{"a.owasp-it.net", "b.owasp-it.net"} {
		if !hasSignal(r, name, "shared-private-addresses") {
			t.Errorf("%s = %+v", name, candidateByID(r, name))
		}
	}
	for _, name := range []string{"single.example", "router.example", "gw2.example"} {
		if hasSignal(r, name, "shared-private-addresses") {
			t.Errorf("%s shares too little to count: %+v", name, candidateByID(r, name))
		}
	}
}

func TestProviderRangesGiveNoHostingSignal(t *testing.T) {
	g := newEvidenceGraph()
	if !hasSignal(signalsReport(t, g), "raiders.example.net", "hosting-in-footprint") {
		t.Fatal("the fixture's hosting signal is missing")
	}

	// once OWASP's netblock is a provider's published range, its tenants are
	// not OWASP's
	g.add("cloudco", "Organization", "Cloud Co", map[string]any{"name": "Cloud Co"})
	g.link("nb-own", "provider", "cloudco", "SimpleRelation")
	if hasSignal(signalsReport(t, g), "raiders.example.net", "hosting-in-footprint") {
		t.Error("a name in a provider's range was taken as hosted by the subject")
	}
}

func TestProviderManagedCertificatesDoNotColist(t *testing.T) {
	// the campus fixture's certificate is publicly issued, so the names it
	// lists are not OWASP's by issuance (signalsFixture's is privately issued)
	g := evidenceGraph{valueGraph{graphtest.CampusGapsFixture()}}
	if !hasSignal(signalsReport(t, g), "owasp-events.com", "certificate-colisting") {
		t.Fatal("the fixture's co-listing signal is missing")
	}

	g.fqdn("sni.cloudflaressl.com")
	g.link("cert", "san_dns_name", "sni.cloudflaressl.com", "SimpleRelation")
	if hasSignal(signalsReport(t, g), "owasp-events.com", "certificate-colisting") {
		t.Error("a CDN's shared certificate co-listed its customers")
	}
}

func TestThirdPartyContactsGiveNoIdentitySignal(t *testing.T) {
	g := newEvidenceGraph()
	g.registered("registrar-customer.example")
	g.add("cr-registrar", "ContactRecord", "https://rdap.example/registrar", nil)
	g.link("dr-registrar-customer.example", "registrar_contact", "cr-registrar", "SimpleRelation")
	g.link("cr-registrar", "phone", "phone", "SimpleRelation")

	r := signalsReport(t, g)
	if c := candidateByID(r, "cr-registrar"); c != nil {
		t.Errorf("a registrar's contact sharing the phone became a candidate: %+v", c)
	}
	if !hasSignal(r, "cr-alt", "shared-registrant-details") {
		t.Errorf("the registrant contact sharing the phone lost its signal: %+v", candidateByID(r, "cr-alt"))
	}
}

func TestCorroboratedPhoneCountsTwice(t *testing.T) {
	count := func(r lens.OwnershipGapReport) int {
		n := 0
		if c := candidateByID(r, "cr-alt"); c != nil {
			for _, s := range c.Signals {
				if s.Signal == "shared-registrant-details" && strings.Contains(s.Via, "Phone") {
					n++
				}
			}
		}
		return n
	}

	g := newEvidenceGraph()
	if n := count(signalsReport(t, g)); n != 1 {
		t.Fatalf("one source gave %d phone signals, want 1", n)
	}

	// OpenStreetMap gives OWASP the same number
	g.add("cr-osm", "ContactRecord", "https://www.openstreetmap.org/node/1", nil)
	g.link("cr-osm", "organization", "owasp", "SimpleRelation")
	g.link("cr-osm", "phone", "phone", "SimpleRelation")
	if n := count(signalsReport(t, g)); n != 2 {
		t.Errorf("a number two sources give OWASP gave %d phone signals, want 2", n)
	}
}

func TestMarkCertificateForTheOrganizationsLEI(t *testing.T) {
	g := newEvidenceGraph()
	g.add("lei", "Identifier", "lei:5493001KJTIIGC8Y1R12", map[string]any{"id": "5493001KJTIIGC8Y1R12", "id_type": "lei"})
	g.link("owasp", "id", "lei", "SimpleRelation")

	g.registered("owasp-brand.com")
	g.add("cert-vmc", "TLSCertificate", "vmc", map[string]any{"serial_number": "vmc",
		"ext_key_usage": []string{"Brand Indicator for Message Identification"}})
	g.add("cr-vmc", "ContactRecord", "vmc-subject", nil)
	g.link("cert-vmc", "subject_contact", "cr-vmc", "SimpleRelation")
	g.link("cr-vmc", "id", "lei", "SimpleRelation")
	g.link("cert-vmc", "common_name", "owasp-brand.com", "SimpleRelation")

	// an ordinary certificate whose subject names the LEI does not count
	g.registered("owasp-plain.com")
	g.add("cert-plain", "TLSCertificate", "plain", map[string]any{"serial_number": "plain"})
	g.add("cr-plain", "ContactRecord", "plain-subject", nil)
	g.link("cert-plain", "subject_contact", "cr-plain", "SimpleRelation")
	g.link("cr-plain", "id", "lei", "SimpleRelation")
	g.link("cert-plain", "common_name", "owasp-plain.com", "SimpleRelation")

	r := signalsReport(t, g)
	if !hasSignal(r, "owasp-brand.com", "mark-certificate-identifier") {
		t.Errorf("owasp-brand.com = %+v", candidateByID(r, "owasp-brand.com"))
	}
	if hasSignal(r, "owasp-plain.com", "mark-certificate-identifier") {
		t.Error("an ordinary certificate counted as a mark certificate")
	}
}

func TestSecurityTxtSharedKey(t *testing.T) {
	g := newEvidenceGraph()
	key := "https://keys.openpgp.org/vks/v1/by-fingerprint/ABCD1234"
	g.add("url-key", "URL", key, map[string]any{"url": key, "host": "keys.openpgp.org"})

	secTxt := func(host string) string {
		file, cr := "file-"+host, "sectxt-"+host
		u := "https://" + host + "/.well-known/security.txt"
		g.add(file, "URL", u, map[string]any{"url": u, "host": host, "path": "/.well-known/security.txt"})
		g.add(cr, "ContactRecord", u, map[string]any{"discovered_at": u})
		g.link(file, "domain", host, "SimpleRelation")
		g.link(file, "contact", cr, "SimpleRelation")
		return cr
	}

	edge := g.link(secTxt("owasp.org"), "url", "url-key", "SimpleRelation")
	g.EvidenceByID[edge] = []graph.Evidence{graphtest.SimpleProp("security_txt_field", "encryption")}

	g.fqdn("owasp-sec.example")
	other := g.link(secTxt("owasp-sec.example"), "url", "url-key", "SimpleRelation")
	g.EvidenceByID[other] = []graph.Evidence{graphtest.SimpleProp("security_txt_field", "encryption")}

	r := signalsReport(t, g)
	if !hasSignal(r, "owasp-sec.example", "security-txt-shared-key") {
		t.Errorf("owasp-sec.example = %+v", candidateByID(r, "owasp-sec.example"))
	}
}

func TestPageNamesOrganization(t *testing.T) {
	g := newEvidenceGraph()
	g.registered("owasp-reunion.com")
	g.add("svc-reunion", "Service", "svc-reunion", map[string]any{
		"output": "<html><footer><p>&copy; 2025 <a href=\"/\">OWASP Foundation</a>. All rights reserved.</p></footer></html>"})
	g.link("owasp-reunion.com", "port", "svc-reunion", "PortRelation")

	// a page that only mentions the name is not the organization's
	g.registered("news.example")
	g.add("svc-news", "Service", "svc-news", map[string]any{
		"output": "<p>OWASP Foundation announced a new dean.</p><footer>© 2025 Example News</footer>"})
	g.link("news.example", "port", "svc-news", "PortRelation")

	r := signalsReport(t, g)
	if !hasSignal(r, "owasp-reunion.com", "page-names-organization") {
		t.Errorf("owasp-reunion.com = %+v", candidateByID(r, "owasp-reunion.com"))
	}
	if hasSignal(r, "news.example", "page-names-organization") {
		t.Error("a news page mentioning the organization counted")
	}
}

func TestPageReferencesBucket(t *testing.T) {
	g := newEvidenceGraph()
	g.add("svc-portal", "Service", "svc-portal", map[string]any{
		"output": `<img src="https://owasp-media.s3.amazonaws.com/logo.png"><a href="https://s3.amazonaws.com/">`})
	g.link("portal.owasp.org", "port", "svc-portal", "PortRelation")
	g.fqdn("owasp-media.s3.amazonaws.com")

	r := signalsReport(t, g)
	if !hasSignal(r, "owasp-media.s3.amazonaws.com", "page-references-bucket") {
		t.Errorf("owasp-media.s3.amazonaws.com = %+v", candidateByID(r, "owasp-media.s3.amazonaws.com"))
	}
}
