// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// postureFixture adds to the vendor fixture what the certificates, domains
// and email lenses read: dated certificates, a dated registration with its
// status, a mail exchanger, and SPF and DMARC records.
func postureFixture() graphtest.VendorGraph {
	g := graphtest.VendorFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	cert := func(id, cn, issuer, notBefore, notAfter, alg string) {
		add(id, "TLSCertificate", id, map[string]any{"serial_number": id, "subject_common_name": cn,
			"issuer_common_name": issuer, "not_before": notBefore, "not_after": notAfter, "signature_algorithm": alg})
	}

	// The fixture's certificate covers www and expires in sixteen days.
	cert("cert", "www.owasp.org", "DigiCert TLS RSA SHA256 2020 CA1", "2026-06-01T00:00:00Z",
		"2026-11-30T00:00:00Z", "SHA256-RSA")
	// An old SHA-1 certificate that expired long ago.
	cert("cert-old", "portal.owasp.org", "Old CA", "2019-01-01T00:00:00Z", "2021-01-01T00:00:00Z", "SHA1-RSA")
	link("cert-old", "common_name", "portal.owasp.org")
	// A self-issued wildcard valid a year from April 2026, also covering a
	// partner's name.
	add("*.owasp.org", "FQDN", "*.owasp.org", map[string]any{"name": "*.owasp.org"})
	add("www.partner-co.com", "FQDN", "www.partner-co.com", map[string]any{"name": "www.partner-co.com"})
	cert("cert-wild", "*.owasp.org", "*.owasp.org", "2026-04-01T00:00:00Z", "2027-04-01T00:00:00Z", "SHA256-RSA")
	link("cert-wild", "common_name", "www.owasp.org")
	link("cert-wild", "san_dns_name", "*.owasp.org")
	link("cert-wild", "san_dns_name", "www.partner-co.com")

	// owasp.org's registration and mail.
	dr := g.Assets["dr"]
	dr.Content = map[string]any{"domain": "owasp.org", "created_date": "1993-05-11",
		"expiration_date": "2027-07-31", "status": []any{"server transfer prohibited"}, "dnssec": false}
	g.Assets["dr"] = dr
	for i, e := range g.Links {
		if e.FromID == "owasp.org" && e.ToID == "mx1.pphosted.com" {
			g.Links[i].Content = map[string]any{"header": map[string]any{"rr_type": 15}, "preference": 10}
		}
	}

	add("_dmarc.owasp.org", "FQDN", "_dmarc.owasp.org", map[string]any{"name": "_dmarc.owasp.org"})
	link("owasp.org", "node", "_dmarc.owasp.org")
	g.EvidenceByID = map[string][]graph.Evidence{
		"owasp.org":        {graphtest.TXTRecord("v=spf1 include:spf.protection.outlook.com ~all")},
		"_dmarc.owasp.org": {graphtest.TXTRecord("v=DMARC1; p=none; rua=mailto:dmarc@owasp.org")},
	}

	return g
}

func postureCatalog() graph.SchemaCatalog {
	return graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}
}

func TestFindCertificates(t *testing.T) {
	defer func(f func() time.Time) { certificateNow = f }(certificateNow)
	certificateNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := postureFixture()
	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Certificates != 3 {
		t.Fatalf("certificates = %d: %+v", r.Certificates, r.Findings)
	}

	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Kind+" "+f.Subject] = true
	}
	for _, want := range []string{CertExpiring + " www.owasp.org", CertExpired + " portal.owasp.org",
		CertWeak + " portal.owasp.org", CertSelfIssued + " *.owasp.org", CertOverlong + " *.owasp.org",
		CertWildcard + " *.owasp.org", CertShared + " *.owasp.org"} {
		if !got[want] {
			t.Errorf("missing %s in %+v", want, r.Findings)
		}
	}
	if got[CertOverlong+" portal.owasp.org"] {
		t.Error("a certificate issued before the validity rules was called overlong")
	}
	if r.Findings[0].Kind != CertExpired {
		t.Errorf("findings are not ordered by severity: %+v", r.Findings)
	}

	text := r.Text()
	for _, w := range []string{"Issued by:", "DigiCert", "Expiring soon (1)", "signed with SHA1-RSA",
		"also covers names of partner-co.com"} {
		if !strings.Contains(text, w) {
			t.Errorf("report lacks %q:\n%s", w, text)
		}
	}
}

func TestCAAAuthorizedCAs(t *testing.T) {
	cas := caaAuthorizedCAs([]string{
		`0 issue "letsencrypt.org"`,
		`0 issuewild "digicert.com; cansignhttpexchanges=yes"`,
		`0 iodef "mailto:security@owasp.org"`,
		`0 issue ";"`,
	})
	want := []string{"digicert.com", "letsencrypt.org"}
	if len(cas) != len(want) {
		t.Fatalf("authorized CAs = %v, want %v", cas, want)
	}
	for i := range want {
		if cas[i] != want[i] {
			t.Fatalf("authorized CAs = %v, want %v", cas, want)
		}
	}
	// A policy of only iodef (no issue/issuewild) authorizes no CA.
	if cas := caaAuthorizedCAs([]string{`0 iodef "mailto:x@y"`}); len(cas) != 0 {
		t.Errorf("iodef-only policy authorized %v", cas)
	}
}

func TestFindCertificatesCAA(t *testing.T) {
	defer func(f func() time.Time) { certificateNow = f }(certificateNow)
	certificateNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	// Without CAA on the apex, the lens reports a no_caa finding.
	g := postureFixture()
	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.AuthorizedCAs) != 0 {
		t.Errorf("authorized CAs without a policy = %+v", r.AuthorizedCAs)
	}
	noCAA := false
	for _, f := range r.Findings {
		if f.Kind == CertNoCAA {
			noCAA = true
		}
	}
	if !noCAA {
		t.Errorf("a domain without CAA was not flagged: %+v", r.Findings)
	}

	// With a CAA policy, the lens reports the authorized CAs and no finding.
	g = postureFixture()
	g.EvidenceByID["owasp.org"] = append(g.EvidenceByID["owasp.org"],
		graphtest.CAARecord(`0 issue "letsencrypt.org"`),
		graphtest.CAARecord(`0 issuewild "digicert.com"`))
	r, err = FindCertificates(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.AuthorizedCAs) != 1 || r.AuthorizedCAs[0].Domain != "owasp.org" ||
		len(r.AuthorizedCAs[0].CAs) != 2 {
		t.Fatalf("authorized CAs = %+v", r.AuthorizedCAs)
	}
	for _, f := range r.Findings {
		if f.Kind == CertNoCAA {
			t.Errorf("a domain with a CAA policy was flagged no_caa: %+v", r.Findings)
		}
	}
	if !strings.Contains(r.Text(), "Authorized to issue (CAA):") {
		t.Errorf("report lacks the CAA section:\n%s", r.Text())
	}
}

// A certificate that names its subject only in its alternative names is
// reported by the first name it covers.
func TestFindCertificatesWithoutCommonName(t *testing.T) {
	defer func(f func() time.Time) { certificateNow = f }(certificateNow)
	certificateNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := postureFixture()
	g.Assets["cert-san"] = graph.Asset{ID: "cert-san", Type: "TLSCertificate", Key: "cert-san",
		Content: map[string]any{"serial_number": "cert-san", "subject_common_name": "",
			"issuer_common_name": "R10", "not_before": "2026-01-01T00:00:00Z", "not_after": "2026-04-01T00:00:00Z",
			"signature_algorithm": "SHA256-RSA"}}
	g.Links = append(g.Links, graph.Relation{ID: "cert-san-san", FromID: "cert-san", ToID: "www.owasp.org",
		Label: "san_dns_name", Type: "SimpleRelation"})

	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if r.Certificates != 4 {
		t.Fatalf("certificates = %d: %+v", r.Certificates, r.Findings)
	}
	found := false
	for _, f := range r.Findings {
		if f.ID == "cert-san" {
			found = true
			if f.Kind != CertExpired || f.Subject != "www.owasp.org" {
				t.Errorf("the certificate without a common name was reported as %s %q", f.Kind, f.Subject)
			}
		}
	}
	if !found {
		t.Errorf("the certificate without a common name was not reported: %+v", r.Findings)
	}
}

func TestFindDomains(t *testing.T) {
	defer func(f func() time.Time) { domainsNow = f }(domainsNow)
	domainsNow = func() time.Time { return time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC) }

	g := postureFixture()
	r, err := FindDomains(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	var owasp DomainEntry
	for _, d := range r.Domains {
		if d.Domain == "owasp.org" {
			owasp = d
		}
	}
	if !owasp.Registered || owasp.Registrar != "EDUCAUSE" || owasp.Expires != "2027-07-31" ||
		len(owasp.NameServers) != 2 {
		t.Fatalf("owasp.org = %+v", owasp)
	}

	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Kind+" "+f.Domain] = true
	}
	if !got[DomainExpiring+" owasp.org"] || !got[DomainNoDNSSEC+" owasp.org"] || got[DomainUnlocked+
		" owasp.org"] {
		t.Errorf("findings = %+v", r.Findings)
	}
	if !strings.Contains(r.Text(), "registrar EDUCAUSE, expires 2027-07-31") {
		t.Errorf("report:\n%s", r.Text())
	}

	// Without a lock status, the domain is reported unlocked.
	dr := g.Assets["dr"]
	dr.Content.(map[string]any)["status"] = []any{"active"}
	r, err = FindDomains(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	unlocked := false
	for _, f := range r.Findings {
		unlocked = unlocked || (f.Kind == DomainUnlocked && f.Domain == "owasp.org")
	}
	if !unlocked {
		t.Errorf("an unlocked domain was not reported: %+v", r.Findings)
	}

	// A record that does not say whether it is signed is not called unsigned.
	delete(dr.Content.(map[string]any), "dnssec")
	r, err = FindDomains(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.Kind == DomainNoDNSSEC {
			t.Errorf("an unstated DNSSEC was reported unsigned: %+v", f)
		}
	}
	if !strings.Contains(r.Text(), "DNSSEC not stated") {
		t.Errorf("report:\n%s", r.Text())
	}
}

func TestFindDomainsZoneTransfer(t *testing.T) {
	defer func(f func() time.Time) { domainsNow = f }(domainsNow)
	domainsNow = func() time.Time { return time.Date(2027, 7, 1, 0, 0, 0, 0, time.UTC) }

	g := postureFixture()
	g.EvidenceByID["owasp.org"] = append(g.EvidenceByID["owasp.org"],
		graphtest.SimpleProp("zone_transfer", "ns1.owasp.org"))

	r, err := FindDomains(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, f := range r.Findings {
		if f.Kind == DomainZoneTransfer && f.Domain == "owasp.org" {
			found = true
		}
	}
	if !found {
		t.Fatalf("a zone transfer exposure was not reported: %+v", r.Findings)
	}
	// It is the most severe finding, so it sorts first.
	if r.Findings[0].Kind != DomainZoneTransfer {
		t.Errorf("zone transfer did not sort to the top: %+v", r.Findings)
	}
	if !strings.Contains(r.Text(), "Zone transfer exposed") {
		t.Errorf("report lacks the zone transfer section:\n%s", r.Text())
	}
}

func TestFindEmailSecurity(t *testing.T) {
	g := postureFixture()
	r, err := FindEmailSecurity(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	var owasp MailDomain
	for _, d := range r.Domains {
		if d.Domain == "owasp.org" {
			owasp = d
		}
	}
	if len(owasp.MailServers) != 1 || owasp.DMARCPolicy != "none" || !strings.HasPrefix(owasp.SPF, "v=spf1") {
		t.Fatalf("owasp.org = %+v", owasp)
	}

	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Kind+" "+f.Domain] = true
	}
	if !got[EmailSPFSoftfail+" owasp.org"] || !got[EmailDMARCMonitor+" owasp.org"] || got[EmailNoSPF+
		" owasp.org"] {
		t.Errorf("findings = %+v", r.Findings)
	}
	if !strings.Contains(r.Text(), "DMARC monitoring only") {
		t.Errorf("report:\n%s", r.Text())
	}
}

func TestSPFAndDMARCParsing(t *testing.T) {
	for rec, want := range map[string]string{
		"v=spf1 -all":                         "-all",
		"v=spf1 include:_spf.google.com ~all": "~all",
		"v=spf1 +all":                         "+all",
		"v=spf1 a mx all":                     "all",
		"v=spf1 redirect=_spf.example.com":    "",
	} {
		if got := spfAll(rec); got != want {
			t.Errorf("spfAll(%q) = %q, want %q", rec, got, want)
		}
	}
	if p := dmarcTag("v=DMARC1; p=Reject; pct=50", "p"); p != "reject" {
		t.Errorf("policy = %q", p)
	}
	if p := dmarcTag("v=DMARC1; p=quarantine; pct=50", "pct"); p != "50" {
		t.Errorf("pct = %q", p)
	}
}

func TestSubjectLensesAreRegistered(t *testing.T) {
	seen := map[string]bool{}
	for _, l := range SubjectLenses() {
		if l.Name == "" || l.Command == "" || l.Find == nil {
			t.Errorf("incomplete lens %+v", l)
		}
		if !l.NeedsOther && (l.Description == "" || len(l.Examples) == 0) {
			t.Errorf("%s has no planner description or examples", l.Name)
		}
		if len(l.Description) > 240 {
			t.Errorf("%s: the description is long (%d chars); every planner prompt carries it", l.Name,
				len(l.Description))
		}
		if seen[l.Name] || seen[l.Command] {
			t.Errorf("%s is registered twice", l.Name)
		}

		seen[l.Name], seen[l.Command] = true, true
	}
}

func TestFindCertificatesMarkCertificate(t *testing.T) {
	defer func(f func() time.Time) { certificateNow = f }(certificateNow)
	certificateNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := postureFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	add("cert-vmc", "TLSCertificate", "cert-vmc", map[string]any{"serial_number": "77",
		"subject_common_name": "OWASP Foundation", "issuer_common_name": "DigiCert Verified Mark RSA4096 SHA256 2021 CA1",
		"not_before": "2026-06-01T00:00:00Z", "not_after": "2027-06-01T00:00:00Z", "signature_algorithm": "SHA256-RSA",
		"ext_key_usage": []any{"Brand Indicator for Message Identification"}})
	link("cert-vmc", "san_dns_name", "owasp.org")
	add("cr-vmc", "ContactRecord", "x509 Certificate: 77, Subject", map[string]any{
		"discovered_at": "x509 Certificate: 77, Subject"})
	link("cert-vmc", "subject_contact", "cr-vmc")
	link("cr-vmc", "organization", "owasp")
	add("tm", "Identifier", "trademark:US:1234567", map[string]any{"unique_id": "trademark:US:1234567",
		"id": "US:1234567", "id_type": "trademark"})
	add("lei", "Identifier", "lei:5493001KJTIIGC8Y1R12", map[string]any{"unique_id": "lei:5493001KJTIIGC8Y1R12",
		"id": "5493001KJTIIGC8Y1R12", "id_type": "lei"})
	link("cr-vmc", "id", "tm")
	link("cr-vmc", "id", "lei")
	// the BIMI record's logo, and the trademark office as the registration's
	// issuing authority
	add("logo", "URL", "https://owasp.org/logo.svg", map[string]any{"url": "https://owasp.org/logo.svg",
		"host": "owasp.org", "path": "/logo.svg"})
	link("cr-vmc", "url", "logo")
	add("cr-office", "ContactRecord", "x509 Certificate: 77, Trademark Office", map[string]any{
		"discovered_at": "x509 Certificate: 77, Trademark Office"})
	add("uspto", "Organization", "uspto", map[string]any{"name": "USPTO"})
	link("tm", "issuing_authority", "cr-office")
	link("cr-office", "organization", "uspto")
	g.EvidenceByID["cr-vmc"] = []graph.Evidence{graphtest.SimpleProp("mark_type", "Registered Mark"),
		graphtest.SimpleProp("word_mark", "OWASP")}

	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.MarkCertificates) != 1 {
		t.Fatalf("mark certificates = %+v, want one", r.MarkCertificates)
	}
	m := r.MarkCertificates[0]
	want := MarkCertificate{Subject: "OWASP Foundation", ID: "cert-vmc", Issuer: m.Issuer,
		NotAfter: "2027-06-01T00:00:00Z", Domains: []string{"owasp.org"}, Organization: "OWASP Foundation",
		MarkType: "Registered Mark", WordMark: "OWASP", Trademark: "US:1234567", TrademarkOffice: "USPTO",
		LEI: "5493001KJTIIGC8Y1R12", Logo: "https://owasp.org/logo.svg"}
	if m.Issuer == "" || !reflect.DeepEqual(m, want) {
		t.Fatalf("mark certificate = %+v\nwant %+v", m, want)
	}

	text := r.Text()
	for _, w := range []string{"Mark certificates (BIMI):", "verified organization OWASP Foundation",
		"trademark US:1234567 (USPTO)", "word mark OWASP", "LEI 5493001KJTIIGC8Y1R12"} {
		if !strings.Contains(text, w) {
			t.Errorf("report lacks %q:\n%s", w, text)
		}
	}
	// the ordinary certificates are not mark certificates
	for _, f := range r.Facts() {
		if strings.HasPrefix(f, "mark_certificate ") && f != "mark_certificate OWASP Foundation" {
			t.Errorf("unexpected fact %q", f)
		}
	}
}

func TestMarkCertificateIsNotOverlong(t *testing.T) {
	defer func(f func() time.Time) { certificateNow = f }(certificateNow)
	certificateNow = func() time.Time { return time.Date(2026, 11, 14, 0, 0, 0, 0, time.UTC) }

	g := postureFixture()
	g.Assets["cert-vmc"] = graph.Asset{ID: "cert-vmc", Type: "TLSCertificate", Key: "cert-vmc",
		Content: map[string]any{"serial_number": "77", "subject_common_name": "OWASP Foundation",
			"issuer_common_name": "Mark CA", "not_before": "2026-06-01T00:00:00Z", "not_after": "2027-06-01T00:00:00Z",
			"signature_algorithm": "SHA256-RSA", "ext_key_usage": []any{"Brand Indicator for Message Identification"}}}
	g.Links = append(g.Links, graph.Relation{ID: "vmc-san", FromID: "cert-vmc", ToID: "owasp.org",
		Label: "san_dns_name", Type: "SimpleRelation"})

	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range r.Findings {
		if f.ID == "cert-vmc" && f.Kind == CertOverlong {
			t.Errorf("a mark certificate was held to the TLS validity limit: %+v", f)
		}
	}
	if len(r.MarkCertificates) != 1 {
		t.Errorf("mark certificates = %+v, want one", r.MarkCertificates)
	}
}
