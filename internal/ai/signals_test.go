// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// valueGraph adds value searches to the campus fixture, over stored TXT
// records (evidence) and asset content.
type valueGraph struct{ graphtest.VendorGraph }

func (g valueGraph) FindByTagValue(_ context.Context, assetType, name, value string, contains bool,
	limit int) ([]graph.Asset, bool, error) {
	var out []graph.Asset
	for id, evs := range g.EvidenceByID {
		a, ok := g.Assets[id]
		if !ok || a.Type != assetType {
			continue
		}
		for _, e := range evs {
			p, _ := e.Property.(map[string]any)
			data, _ := p["data"].(string)
			if data == "" {
				data, _ = p["property_value"].(string)
			}
			if p["property_name"] != name {
				continue
			}
			if (!contains && data == value) || (contains && strings.Contains(strings.ToLower(data),
				strings.ToLower(value))) {
				out = append(out, a)
				break
			}
		}
	}

	slices.SortFunc(out, func(a, b graph.Asset) int { return strings.Compare(a.ID, b.ID) })
	if len(out) > limit {
		return out[:limit], true, nil
	}

	return out, false, nil
}

func (g valueGraph) FindByAttribute(_ context.Context, assetType, key, value string, contains bool,
	limit int) ([]graph.Asset, bool, error) {
	var out []graph.Asset
	for _, a := range g.Assets {
		if a.Type != assetType {
			continue
		}

		text := graph.ContentString(a, key)
		if !contains && text == value {
			out = append(out, a)
		} else if contains {
			data, _ := json.Marshal(lens.ContentValue(a, key))
			if strings.Contains(strings.ToLower(string(data)), strings.ToLower(value)) {
				out = append(out, a)
			}
		}
	}

	slices.SortFunc(out, func(a, b graph.Asset) int { return strings.Compare(a.ID, b.ID) })
	if len(out) > limit {
		return out[:limit], true, nil
	}

	return out, false, nil
}

// signalsFixture extends the campus with evidence for each value signal:
//   - colgate-arts.org shares Colgate's site verification token and
//     includes Colgate's SPF;
//   - colgate-news.org sends DMARC reports to colgate.edu;
//   - colgate-portal.net has a certificate with the key and private issuer
//     of Colgate's certificate;
//   - hamco.org uses Colgate's name server.
func signalsFixture() valueGraph {
	g := valueGraph{graphtest.CampusGapsFixture()}
	g.EvidenceByID = map[string][]graph.Evidence{}
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }
	link := func(from, label, to, rt string, content any) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt, Content: content})
	}
	registered := func(domain string) {
		named(domain, "FQDN", domain)
		add("dr-"+domain, "DomainRecord", domain, map[string]any{"domain": domain})
		add("cr-"+domain, "ContactRecord", "https://rdap.example/"+domain, nil)
		link(domain, "registration", "dr-"+domain, "SimpleRelation", nil)
		link("dr-"+domain, "registrant_contact", "cr-"+domain, "SimpleRelation", nil)
	}

	g.EvidenceByID["colgate.edu"] = []graph.Evidence{graphtest.TXTRecord("google-site-verification=colgate-token"),
		graphtest.TXTRecord("v=spf1 include:_spf.google.com ~all")}

	registered("colgate-arts.org")
	g.EvidenceByID["colgate-arts.org"] = []graph.Evidence{graphtest.TXTRecord("google-site-verification=colgate-token"),
		graphtest.TXTRecord("v=spf1 include:_spf.colgate.edu ~all")}

	registered("colgate-news.org")
	named("_dmarc.colgate-news.org", "FQDN", "_dmarc.colgate-news.org")
	link("colgate-news.org", "node", "_dmarc.colgate-news.org", "SimpleRelation", nil)
	g.EvidenceByID["_dmarc.colgate-news.org"] = []graph.Evidence{graphtest.TXTRecord("v=DMARC1; p=none; rua=mailto:dmarc@colgate.edu")}

	// A look-alike that only contains the name never counts.
	registered("notcolgate.edu.example")
	g.EvidenceByID["notcolgate.edu.example"] = []graph.Evidence{graphtest.TXTRecord("v=spf1 include:mail.notcolgate.edu ~all")}

	g.Assets["cert"] = graph.Asset{ID: "cert", Type: "TLSCertificate", Key: "1234", Content: map[string]any{
		"serial_number": "1234", "subject_key_id": "aa:bb", "authority_key_id": "ca:01",
		"issuer_common_name": "Colgate Internal CA"}}
	link("cert", "common_name", "www.colgate.edu", "SimpleRelation", nil)
	// Colgate's issuing CA and its root: a private chain.
	add("ca-int", "TLSCertificate", "ca-int", map[string]any{"serial_number": "ca-int",
		"subject_common_name": "Colgate Internal CA", "issuer_common_name": "Colgate Root CA", "is_ca": true})
	add("ca-root", "TLSCertificate", "ca-root", map[string]any{"serial_number": "ca-root",
		"subject_common_name": "Colgate Root CA", "issuer_common_name": "Colgate Root CA", "is_ca": true})
	link("cert", "issuing_certificate", "ca-int", "SimpleRelation", nil)
	link("ca-int", "issuing_certificate", "ca-root", "SimpleRelation", nil)
	add("cert-portal", "TLSCertificate", "5678", map[string]any{"serial_number": "5678", "subject_key_id": "aa:bb",
		"authority_key_id": "ca:01", "issuer_common_name": "Colgate Internal CA"})
	registered("colgate-portal.net")
	link("cert-portal", "common_name", "colgate-portal.net", "SimpleRelation", nil)

	link("colgate.edu", "node", "ns1.colgate.edu", "SimpleRelation", nil)
	registered("hamco.org")
	link("dr-hamco.org", "name_server", "ns1.colgate.edu", "SimpleRelation", nil)
	link("hamco.org", "dns_record", "ns1.colgate.edu", "BasicDNSRelation",
		map[string]any{"header": map[string]any{"rr_type": lens.RRTypeNS}})
	return g
}

func signalsReport(t *testing.T, g graph.Graph) lens.OwnershipGapReport {
	t.Helper()

	r, err := lens.SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, graph.Asset{ID: "colgate",
		Type: "Organization", Key: "Colgate University", Content: map[string]any{"name": "Colgate University"}})
	if err != nil {
		t.Fatal(err)
	}

	return r
}

// candidateByID finds a candidate by asset ID; a domain record and its
// name share a label.
func candidateByID(r lens.OwnershipGapReport, id string) *lens.GapCandidate {
	for i, c := range r.Candidates {
		if c.AssetID == id {
			return &r.Candidates[i]
		}
	}

	return nil
}

func signalIDs(c *lens.GapCandidate) []string {
	var out []string
	for _, s := range c.Signals {
		if !slices.Contains(out, s.Signal) {
			out = append(out, s.Signal)
		}
	}

	slices.Sort(out)
	return out
}

func TestVerificationTokenAndSPFPropose(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	c := candidateByID(r, "colgate-arts.org")
	if c == nil {
		t.Fatalf("colgate-arts.org is not a candidate: %+v", r.Candidates)
	}
	if got := signalIDs(c); !slices.Equal(got, []string{"email_auth_reference", "name_token",
		"txt_verification_token"}) {
		t.Errorf("signals = %v", got)
	}
	if c.Decision != lens.GapPropose || c.Attachment == nil ||
		c.Attachment.String() != "ContactRecord https://rdap.example/colgate-arts.org --organization--> Organization Colgate University" {
		t.Errorf("decision %s, attachment %v", c.Decision, c.Attachment)
	}

	var details []string
	for _, s := range c.Signals {
		for _, w := range s.Witness {
			if w.RelationType == "MatchedValue" {
				details = append(details, w.Label+" "+w.Detail)
			}
		}
	}
	if !slices.Contains(details, "same_txt_token google-site-verification=") ||
		!slices.Contains(details, "txt_reference include:_spf.colgate.edu") {
		t.Errorf("matched-value witnesses = %v", details)
	}
}

func TestDMARCReportsNameTheDomainNotTheRecord(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	if c := gapCandidate(r, "_dmarc.colgate-news.org"); c != nil {
		t.Errorf("the DMARC record name became a candidate: %+v", c)
	}

	// One strong signal and a name token: the token is a tiebreaker, so it
	// does not corroborate the strong signal into a proposal.
	c := candidateByID(r, "colgate-news.org")
	if c == nil || !slices.Equal(signalIDs(c), []string{"email_auth_reference", "name_token"}) ||
		c.Decision != lens.GapReview {
		t.Errorf("colgate-news.org = %+v", c)
	}
}

func TestLookAlikeReferencesDoNotCount(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	if c := gapCandidate(r, "notcolgate.edu.example"); c != nil {
		t.Errorf("a name that only contains the domain became a candidate: %+v", c)
	}
}

func TestCertificateKeyAndPrivateIssuer(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	c := candidateByID(r, "colgate-portal.net")
	if c == nil {
		t.Fatalf("colgate-portal.net is not a candidate: %+v", r.Candidates)
	}
	if got := signalIDs(c); !slices.Equal(got, []string{"certificate_key_reuse", "name_token",
		"private_ca_issuance"}) {
		t.Errorf("signals = %v", got)
	}
	if c.Decision != lens.GapPropose {
		t.Errorf("decision = %s", c.Decision)
	}
}

func TestPublicIssuersAreNotPrivateCAs(t *testing.T) {
	g := signalsFixture()
	for _, id := range []string{"cert", "cert-portal"} {
		a := g.Assets[id]
		a.Content.(map[string]any)["issuer_common_name"] = "R3"
		a.Content.(map[string]any)["subject_key_id"] = "key-" + id
		g.Assets[id] = a
	}

	if c := candidateByID(signalsReport(t, g), "colgate-portal.net"); c != nil {
		t.Errorf("a public issuer linked certificates: %+v", c)
	}
	for _, tc := range []struct {
		issuer string
		public bool
	}{{"R3", true}, {"Let's Encrypt Authority X3", true}, {"Partner3 Root", false}, {"Colgate Internal CA", false},
		{"DigiCert Global G2 TLS RSA SHA256 2020 CA1", true}} {
		def, _ := lens.LookupOwnershipSignal("private_ca_issuance")
		if got := lens.PublicIssuer(tc.issuer, def.Params.PublicIssuers); got != tc.public {
			t.Errorf("publicIssuer(%q) = %v", tc.issuer, got)
		}
	}
}

func TestSelfHostedNameServers(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	c := candidateByID(r, "hamco.org")
	if c == nil || !slices.Equal(signalIDs(c), []string{"self_hosted_dns"}) {
		t.Fatalf("hamco.org = %+v", c)
	}
	if !strings.Contains(c.Signals[0].Via, " NS ") {
		t.Errorf("via = %q, want the record type", c.Signals[0].Via)
	}
	if dr := candidateByID(r, "dr-hamco.org"); dr == nil || !slices.Equal(signalIDs(dr), []string{"self_hosted_dns"}) {
		t.Errorf("the domain record with Colgate's name server = %+v", dr)
	}
}

func TestWidelySharedTokensDoNotCount(t *testing.T) {
	g := signalsFixture()
	for i := 0; i <= lens.GapMaxShared; i++ {
		id := fmt.Sprintf("tenant%d.example", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: id, Content: map[string]any{"name": id}}
		g.EvidenceByID[id] = []graph.Evidence{graphtest.TXTRecord("google-site-verification=colgate-token")}
	}

	c := candidateByID(signalsReport(t, g), "colgate-arts.org")
	if c == nil || slices.Contains(signalIDs(c), "txt_verification_token") {
		t.Errorf("a token on %d domains still counted: %+v", lens.GapMaxShared+1, c)
	}
}

func TestValueSignalsNeedAValueSearcher(t *testing.T) {
	g := signalsFixture()
	r := signalsReport(t, g.VendorGraph)
	if c := candidateByID(r, "colgate-arts.org"); c != nil {
		t.Errorf("value signals ran without value searches: %+v", c)
	}
	if c := candidateByID(r, "hamco.org"); c == nil {
		t.Error("relationship signals stopped without value searches")
	}
}

func TestProposalsExplainTheirSignals(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	var p *review.OwnershipProposal
	for _, q := range review.OwnershipProposals(r) {
		if q.AssetID == "colgate-arts.org" {
			p = &q
		}
	}
	if p == nil {
		t.Fatal("no proposal for colgate-arts.org's contact")
	}

	text := review.FormatOwnershipEntries([]review.OwnershipEntry{{Proposal: *p, Status: review.ProposalPending}})
	for _, want := range []string{"why: Shared DNS verification token (strong):",
		"why: Email authentication delegated to the organization (strong):"} {
		if !strings.Contains(text, want) {
			t.Errorf("listing lacks %q:\n%s", want, text)
		}
	}
	if f := OwnershipFeatures(*p); f["signal:txt_verification_token"] != 1 {
		t.Errorf("features = %v", f)
	}
}

// Live review: owasp.org shared an issuing key with calendar.colgate.edu
// because both had certificates from a public intermediate with a short name
// (WE1) that the public list lacked. Its chain reaches a public root.
func TestPublicIntermediatesAreFoundThroughTheChain(t *testing.T) {
	g := signalsFixture()
	add := func(id, cn, issuer string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "TLSCertificate", Key: id, Content: map[string]any{"serial_number": id,
			"subject_common_name": cn, "issuer_common_name": issuer, "authority_key_id": "AA:BB:CC",
			"subject_key_id": id}}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	add("cert-cal", "calendar.colgate.edu", "WE1")
	add("we1", "WE1", "GTS Root R4")
	link("cert-cal", "common_name", "portal.colgate.edu")
	link("cert-cal", "issuing_certificate", "we1")
	add("cert-owasp", "owasp.org", "WE1")
	g.Assets["owasp.org"] = graph.Asset{ID: "owasp.org", Type: "FQDN", Key: "owasp.org",
		Content: map[string]any{"name": "owasp.org"}}
	link("cert-owasp", "common_name", "owasp.org")

	if c := candidateByID(signalsReport(t, g), "owasp.org"); c != nil {
		t.Errorf("a certificate from a public intermediate counted as a private CA: %+v", c)
	}
}

func TestNamesUnderOwnedDomainsAreOwned(t *testing.T) {
	g := signalsFixture()
	g.Assets["csvm02"] = graph.Asset{ID: "csvm02", Type: "FQDN", Key: "csvm02.colgate.edu",
		Content: map[string]any{"name": "csvm02.colgate.edu"}}
	g.Links = append(g.Links, graph.Relation{ID: "csvm02-dns", FromID: "csvm02", ToID: "ip-own", Label: "dns_record",
		Type: "BasicDNSRelation"})

	if c := candidateByID(signalsReport(t, g), "csvm02"); c != nil {
		t.Errorf("a name under colgate.edu became a candidate: %+v", c)
	}
}

// TestRegistrantEmailDomainSignal: an unowned domain whose registrant uses a
// different mailbox at the same custom domain as a controlled registration is
// linked by the email-domain signal, while a shared free-mail domain is not.
func TestRegistrantEmailDomainSignal(t *testing.T) {
	g := signalsFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	email := func(id, addr string) {
		add(id, "Identifier", id, map[string]any{"id": addr, "id_type": "email"})
	}
	sibling := func(domain, crID, idID, addr string) {
		add(domain, "FQDN", domain, map[string]any{"name": domain})
		add("dr-"+domain, "DomainRecord", domain, map[string]any{"domain": domain})
		add(crID, "ContactRecord", "https://rdap.example/"+crID, nil)
		email(idID, addr)
		link(domain, "registration", "dr-"+domain)
		link("dr-"+domain, "registrant_contact", crID)
		link(crID, "id", idID)
	}

	// Colgate's controlled registration contact has a custom-domain mailbox
	// and a free-webmail one.
	email("email:admin@colgate.edu", "admin@colgate.edu")
	email("email:colgate.alumni@gmail.com", "colgate.alumni@gmail.com")
	link("cr-colgate", "id", "email:admin@colgate.edu")
	link("cr-colgate", "id", "email:colgate.alumni@gmail.com")

	// An unowned domain registered with a different mailbox at colgate.edu,
	// and one sharing only the gmail.com webmail domain.
	sibling("colgate-labs.org", "cr-labs", "email:webmaster@colgate.edu", "webmaster@colgate.edu")
	sibling("free.example", "cr-free", "email:someone@gmail.com", "someone@gmail.com")

	r := signalsReport(t, g)

	c := candidateByID(r, "cr-labs")
	if c == nil {
		t.Fatalf("cr-labs is not a candidate: %+v", r.Candidates)
	}
	if !slices.Contains(signalIDs(c), "shared_registrant_email_domain") {
		t.Errorf("cr-labs signals = %v, want shared_registrant_email_domain", signalIDs(c))
	}
	// One strong signal alone waits for review, and it attaches to the subject.
	if c.Decision != lens.GapReview || c.Attachment == nil ||
		c.Attachment.String() != "ContactRecord https://rdap.example/cr-labs --organization--> Organization Colgate University" {
		t.Errorf("decision %s, attachment %v", c.Decision, c.Attachment)
	}

	// A shared free-webmail domain identifies no owner, so it gives no signal.
	if fc := candidateByID(r, "cr-free"); fc != nil && slices.Contains(signalIDs(fc), "shared_registrant_email_domain") {
		t.Errorf("a free-mail domain gave an email-domain signal: %+v", fc)
	}
}

// TestEmailDomainSignalSpansIPAndDomainRegistrations: the email domain of a
// controlled IP-network registration contact links an unowned domain whose
// registrant uses the same mail domain, across registration kinds.
func TestEmailDomainSignalSpansIPAndDomainRegistrations(t *testing.T) {
	g := signalsFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	email := func(id, addr string) { add(id, "Identifier", id, map[string]any{"id": addr, "id_type": "email"}) }

	// Colgate's controlled network registration has its own operations contact
	// at a custom mail domain.
	add("cr-netops", "ContactRecord", "https://rdap.example/netops", nil)
	email("email:noc@colgate-net.example", "noc@colgate-net.example")
	link("ipnet-own", "registrant", "cr-netops")
	link("cr-netops", "id", "email:noc@colgate-net.example")

	// An unowned domain registered with a different mailbox at that same mail
	// domain: the same operator, found across network and domain registration.
	add("partner.example", "FQDN", "partner.example", map[string]any{"name": "partner.example"})
	add("dr-partner", "DomainRecord", "partner.example", map[string]any{"domain": "partner.example"})
	add("cr-partner", "ContactRecord", "https://rdap.example/partner", nil)
	email("email:admin@colgate-net.example", "admin@colgate-net.example")
	link("partner.example", "registration", "dr-partner")
	link("dr-partner", "registrant_contact", "cr-partner")
	link("cr-partner", "id", "email:admin@colgate-net.example")

	r := signalsReport(t, g)
	c := candidateByID(r, "cr-partner")
	if c == nil {
		t.Fatalf("cr-partner is not a candidate: %+v", r.Candidates)
	}
	if !slices.Contains(signalIDs(c), "shared_registrant_email_domain") {
		t.Errorf("cr-partner signals = %v, want shared_registrant_email_domain", signalIDs(c))
	}
}

// TestDKIMKeyReuseSignal: an unowned domain publishing the same DKIM public
// key as a controlled domain is linked by the DKIM-key signal.
func TestDKIMKeyReuseSignal(t *testing.T) {
	g := signalsFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	fqdn := func(name string) { add(name, "FQDN", name, map[string]any{"name": name}) }
	link := func(from, label, to string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: "SimpleRelation"})
	}
	txt := "v=DKIM1; k=rsa; p=" + strings.Repeat("A", 216)

	// Colgate's controlled apex publishes a DKIM key under a selector.
	fqdn("sel._domainkey.colgate.edu")
	link("colgate.edu", "node", "sel._domainkey.colgate.edu")
	g.EvidenceByID["sel._domainkey.colgate.edu"] = []graph.Evidence{graphtest.TXTRecord(txt)}

	// An unowned domain publishes the same DKIM key under its own selector.
	fqdn("colgate-mail.org")
	add("dr-mail", "DomainRecord", "colgate-mail.org", map[string]any{"domain": "colgate-mail.org"})
	add("cr-mail", "ContactRecord", "https://rdap.example/mail", nil)
	fqdn("default._domainkey.colgate-mail.org")
	link("colgate-mail.org", "registration", "dr-mail")
	link("dr-mail", "registrant_contact", "cr-mail")
	link("colgate-mail.org", "node", "default._domainkey.colgate-mail.org")
	g.EvidenceByID["default._domainkey.colgate-mail.org"] = []graph.Evidence{graphtest.TXTRecord(txt)}

	r := signalsReport(t, g)
	c := candidateByID(r, "colgate-mail.org")
	if c == nil {
		t.Fatalf("colgate-mail.org is not a candidate: %+v", r.Candidates)
	}
	if !slices.Contains(signalIDs(c), "dkim_key_reuse") {
		t.Errorf("colgate-mail.org signals = %v, want dkim_key_reuse", signalIDs(c))
	}
}

// TestSecurityTxtReferenceSignal: an unowned service whose security.txt points
// its canonical URL, or its security contact, into the organization's
// namespace is linked by the security_txt_reference signal.
func TestSecurityTxtReferenceSignal(t *testing.T) {
	g := signalsFixture()
	add := func(id, typ string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: id, Content: content}
	}
	fqdn := func(name string) { add(name, "FQDN", map[string]any{"name": name}) }
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to,
			Label: label, Type: rt})
	}

	// An unowned site whose security.txt canonical URL is in colgate.edu.
	fqdn("partner-run.example")
	add("svc-a", "Service", map[string]any{"service_type": "web-service"})
	add("url-canon", "URL", map[string]any{"url": "https://colgate.edu/.well-known/security.txt",
		"host": "colgate.edu"})
	link("partner-run.example", "port", "svc-a", "PortRelation")
	link("svc-a", "security_canonical", "url-canon", "SimpleRelation")

	// An unowned site whose security contact is a mailbox at colgate.edu.
	fqdn("vendor-site.example")
	add("svc-b", "Service", map[string]any{"service_type": "web-service"})
	add("cr-b", "ContactRecord", nil)
	add("id-b", "Identifier", map[string]any{"id": "security@colgate.edu", "id_type": "email"})
	link("vendor-site.example", "port", "svc-b", "PortRelation")
	link("svc-b", "security_contact", "cr-b", "SimpleRelation")
	link("cr-b", "id", "id-b", "SimpleRelation")

	r := signalsReport(t, g)
	for _, id := range []string{"partner-run.example", "vendor-site.example"} {
		c := candidateByID(r, id)
		if c == nil {
			t.Errorf("%s is not a candidate: %+v", id, r.Candidates)
			continue
		}
		if !slices.Contains(signalIDs(c), "security_txt_reference") {
			t.Errorf("%s signals = %v, want security_txt_reference", id, signalIDs(c))
		}
	}
}
