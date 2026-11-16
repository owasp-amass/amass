// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
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
	cert("cert", "www.colgate.edu", "DigiCert TLS RSA SHA256 2020 CA1", "2026-06-01T00:00:00Z",
		"2026-11-30T00:00:00Z", "SHA256-RSA")
	// An old SHA-1 certificate that expired long ago.
	cert("cert-old", "portal.colgate.edu", "Old CA", "2019-01-01T00:00:00Z", "2021-01-01T00:00:00Z", "SHA1-RSA")
	link("cert-old", "common_name", "portal.colgate.edu")
	// A self-issued wildcard valid a year from April 2026, also covering a
	// partner's name.
	add("*.colgate.edu", "FQDN", "*.colgate.edu", map[string]any{"name": "*.colgate.edu"})
	add("www.partner-co.com", "FQDN", "www.partner-co.com", map[string]any{"name": "www.partner-co.com"})
	cert("cert-wild", "*.colgate.edu", "*.colgate.edu", "2026-04-01T00:00:00Z", "2027-04-01T00:00:00Z", "SHA256-RSA")
	link("cert-wild", "common_name", "www.colgate.edu")
	link("cert-wild", "san_dns_name", "*.colgate.edu")
	link("cert-wild", "san_dns_name", "www.partner-co.com")

	// colgate.edu's registration and mail.
	dr := g.Assets["dr"]
	dr.Content = map[string]any{"domain": "colgate.edu", "created_date": "1993-05-11",
		"expiration_date": "2027-07-31", "status": []any{"server transfer prohibited"}, "dnssec": false}
	g.Assets["dr"] = dr
	for i, e := range g.Links {
		if e.FromID == "colgate.edu" && e.ToID == "mx1.pphosted.com" {
			g.Links[i].Content = map[string]any{"header": map[string]any{"rr_type": 15}, "preference": 10}
		}
	}

	add("_dmarc.colgate.edu", "FQDN", "_dmarc.colgate.edu", map[string]any{"name": "_dmarc.colgate.edu"})
	link("colgate.edu", "node", "_dmarc.colgate.edu")
	g.EvidenceByID = map[string][]graph.Evidence{
		"colgate.edu":        {graphtest.TXTRecord("v=spf1 include:spf.protection.outlook.com ~all")},
		"_dmarc.colgate.edu": {graphtest.TXTRecord("v=DMARC1; p=none; rua=mailto:dmarc@colgate.edu")},
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
	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
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
	for _, want := range []string{CertExpiring + " www.colgate.edu", CertExpired + " portal.colgate.edu",
		CertWeak + " portal.colgate.edu", CertSelfIssued + " *.colgate.edu", CertOverlong + " *.colgate.edu",
		CertWildcard + " *.colgate.edu", CertShared + " *.colgate.edu"} {
		if !got[want] {
			t.Errorf("missing %s in %+v", want, r.Findings)
		}
	}
	if got[CertOverlong+" portal.colgate.edu"] {
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
		`0 iodef "mailto:security@colgate.edu"`,
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
	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
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
	g.EvidenceByID["colgate.edu"] = append(g.EvidenceByID["colgate.edu"],
		graphtest.CAARecord(`0 issue "letsencrypt.org"`),
		graphtest.CAARecord(`0 issuewild "digicert.com"`))
	r, err = FindCertificates(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(r.AuthorizedCAs) != 1 || r.AuthorizedCAs[0].Domain != "colgate.edu" ||
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
	g.Links = append(g.Links, graph.Relation{ID: "cert-san-san", FromID: "cert-san", ToID: "www.colgate.edu",
		Label: "san_dns_name", Type: "SimpleRelation"})

	r, err := FindCertificates(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
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
			if f.Kind != CertExpired || f.Subject != "www.colgate.edu" {
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
	r, err := FindDomains(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	var colgate DomainEntry
	for _, d := range r.Domains {
		if d.Domain == "colgate.edu" {
			colgate = d
		}
	}
	if !colgate.Registered || colgate.Registrar != "EDUCAUSE" || colgate.Expires != "2027-07-31" ||
		len(colgate.NameServers) != 2 {
		t.Fatalf("colgate.edu = %+v", colgate)
	}

	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Kind+" "+f.Domain] = true
	}
	if !got[DomainExpiring+" colgate.edu"] || !got[DomainNoDNSSEC+" colgate.edu"] || got[DomainUnlocked+
		" colgate.edu"] {
		t.Errorf("findings = %+v", r.Findings)
	}
	if !strings.Contains(r.Text(), "registrar EDUCAUSE, expires 2027-07-31") {
		t.Errorf("report:\n%s", r.Text())
	}

	// Without a lock status, the domain is reported unlocked.
	dr := g.Assets["dr"]
	dr.Content.(map[string]any)["status"] = []any{"active"}
	r, err = FindDomains(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	unlocked := false
	for _, f := range r.Findings {
		unlocked = unlocked || (f.Kind == DomainUnlocked && f.Domain == "colgate.edu")
	}
	if !unlocked {
		t.Errorf("an unlocked domain was not reported: %+v", r.Findings)
	}

	// A record that does not say whether it is signed is not called unsigned.
	delete(dr.Content.(map[string]any), "dnssec")
	r, err = FindDomains(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
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
	g.EvidenceByID["colgate.edu"] = append(g.EvidenceByID["colgate.edu"],
		graphtest.SimpleProp("zone_transfer", "ns1.colgate.edu"))

	r, err := FindDomains(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	var found bool
	for _, f := range r.Findings {
		if f.Kind == DomainZoneTransfer && f.Domain == "colgate.edu" {
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
	r, err := FindEmailSecurity(context.Background(), g, postureCatalog(), g.Assets["colgate.edu"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	var colgate MailDomain
	for _, d := range r.Domains {
		if d.Domain == "colgate.edu" {
			colgate = d
		}
	}
	if len(colgate.MailServers) != 1 || colgate.DMARCPolicy != "none" || !strings.HasPrefix(colgate.SPF, "v=spf1") {
		t.Fatalf("colgate.edu = %+v", colgate)
	}

	got := map[string]bool{}
	for _, f := range r.Findings {
		got[f.Kind+" "+f.Domain] = true
	}
	if !got[EmailSPFSoftfail+" colgate.edu"] || !got[EmailDMARCMonitor+" colgate.edu"] || got[EmailNoSPF+
		" colgate.edu"] {
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
