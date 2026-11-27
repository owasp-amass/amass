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
	if limit > 0 && len(out) > limit {
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
	if limit > 0 && len(out) > limit {
		return out[:limit], true, nil
	}

	return out, false, nil
}

// signalsFixture extends the campus with evidence for each value signal:
//   - owasp-arts.org shares OWASP's site verification token and
//     includes OWASP's SPF;
//   - owasp-news.org sends DMARC reports to owasp.org;
//   - owasp-portal.net has a certificate with the key and private issuer
//     of OWASP's certificate;
//   - hamco.org uses OWASP's name server.
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

	g.EvidenceByID["owasp.org"] = []graph.Evidence{graphtest.TXTRecord("google-site-verification=owasp-token"),
		graphtest.TXTRecord("v=spf1 include:_spf.google.com ~all")}

	registered("owasp-arts.org")
	g.EvidenceByID["owasp-arts.org"] = []graph.Evidence{graphtest.TXTRecord("google-site-verification=owasp-token"),
		graphtest.TXTRecord("v=spf1 include:_spf.owasp.org ~all")}

	registered("owasp-news.org")
	named("_dmarc.owasp-news.org", "FQDN", "_dmarc.owasp-news.org")
	link("owasp-news.org", "node", "_dmarc.owasp-news.org", "SimpleRelation", nil)
	g.EvidenceByID["_dmarc.owasp-news.org"] = []graph.Evidence{graphtest.TXTRecord("v=DMARC1; p=none; rua=mailto:dmarc@owasp.org")}

	// A look-alike that only contains the name never counts.
	registered("notowasp.org.example")
	g.EvidenceByID["notowasp.org.example"] = []graph.Evidence{graphtest.TXTRecord("v=spf1 include:mail.notowasp.org ~all")}

	g.Assets["cert"] = graph.Asset{ID: "cert", Type: "TLSCertificate", Key: "1234", Content: map[string]any{
		"serial_number": "1234", "subject_key_id": "aa:bb", "authority_key_id": "ca:01",
		"issuer_common_name": "OWASP Internal CA"}}
	link("cert", "common_name", "www.owasp.org", "SimpleRelation", nil)
	// OWASP's issuing CA and its root: a private chain.
	add("ca-int", "TLSCertificate", "ca-int", map[string]any{"serial_number": "ca-int",
		"subject_common_name": "OWASP Internal CA", "issuer_common_name": "OWASP Root CA", "is_ca": true})
	add("ca-root", "TLSCertificate", "ca-root", map[string]any{"serial_number": "ca-root",
		"subject_common_name": "OWASP Root CA", "issuer_common_name": "OWASP Root CA", "is_ca": true})
	link("cert", "issuing_certificate", "ca-int", "SimpleRelation", nil)
	link("ca-int", "issuing_certificate", "ca-root", "SimpleRelation", nil)
	add("cert-portal", "TLSCertificate", "5678", map[string]any{"serial_number": "5678", "subject_key_id": "aa:bb",
		"authority_key_id": "ca:01", "issuer_common_name": "OWASP Internal CA"})
	registered("owasp-portal.net")
	link("cert-portal", "common_name", "owasp-portal.net", "SimpleRelation", nil)

	link("owasp.org", "node", "ns1.owasp.org", "SimpleRelation", nil)
	registered("hamco.org")
	link("dr-hamco.org", "name_server", "ns1.owasp.org", "SimpleRelation", nil)
	link("hamco.org", "dns_record", "ns1.owasp.org", "BasicDNSRelation",
		map[string]any{"header": map[string]any{"rr_type": lens.RRTypeNS}})
	return g
}

func signalsReport(t *testing.T, g graph.Graph) lens.OwnershipGapReport {
	t.Helper()

	r, err := lens.SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, graph.Asset{ID: "owasp",
		Type: "Organization", Key: "OWASP Foundation", Content: map[string]any{"name": "OWASP Foundation"}})
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
	c := candidateByID(r, "owasp-arts.org")
	if c == nil {
		t.Fatalf("owasp-arts.org is not a candidate: %+v", r.Candidates)
	}
	if got := signalIDs(c); !slices.Equal(got, []string{"name-token", "spf-authorizes",
		"txt-verification-token"}) {
		t.Errorf("signals = %v", got)
	}
	if c.Decision != lens.GapPropose || c.Attachment == nil ||
		c.Attachment.String() != "ContactRecord https://rdap.example/owasp-arts.org --organization--> Organization OWASP Foundation" {
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
		!slices.Contains(details, "txt_reference include:_spf.owasp.org") {
		t.Errorf("matched-value witnesses = %v", details)
	}
}

func TestDMARCReportsNameTheDomainNotTheRecord(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	if c := gapCandidate(r, "_dmarc.owasp-news.org"); c != nil {
		t.Errorf("the DMARC record name became a candidate: %+v", c)
	}

	// One strong signal and a name token: the token is a tiebreaker, so it
	// does not corroborate the strong signal into a proposal.
	c := candidateByID(r, "owasp-news.org")
	if c == nil || !slices.Equal(signalIDs(c), []string{"name-token", "spf-authorizes"}) ||
		c.Decision != lens.GapReview {
		t.Errorf("owasp-news.org = %+v", c)
	}
}

func TestLookAlikeReferencesDoNotCount(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	if c := gapCandidate(r, "notowasp.org.example"); c != nil {
		t.Errorf("a name that only contains the domain became a candidate: %+v", c)
	}
}

func TestCertificateKeyAndPrivateIssuer(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	c := candidateByID(r, "owasp-portal.net")
	if c == nil {
		t.Fatalf("owasp-portal.net is not a candidate: %+v", r.Candidates)
	}
	if got := signalIDs(c); !slices.Equal(got, []string{"certificate-key-reuse", "name-token",
		"private-ca-issuance"}) {
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

	if c := candidateByID(signalsReport(t, g), "owasp-portal.net"); c != nil {
		t.Errorf("a public issuer linked certificates: %+v", c)
	}
	for _, tc := range []struct {
		issuer string
		public bool
	}{{"R3", true}, {"Let's Encrypt Authority X3", true}, {"Partner3 Root", false}, {"OWASP Internal CA", false},
		{"DigiCert Global G2 TLS RSA SHA256 2020 CA1", true}} {
		if got := lens.PublicIssuer(tc.issuer); got != tc.public {
			t.Errorf("publicIssuer(%q) = %v", tc.issuer, got)
		}
	}
}

func TestSelfHostedNameServers(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	c := candidateByID(r, "hamco.org")
	if c == nil || !slices.Equal(signalIDs(c), []string{"self-hosted-dns"}) {
		t.Fatalf("hamco.org = %+v", c)
	}
	if !strings.Contains(c.Signals[0].Via, " NS ") {
		t.Errorf("via = %q, want the record type", c.Signals[0].Via)
	}
	if dr := candidateByID(r, "dr-hamco.org"); dr == nil || !slices.Equal(signalIDs(dr), []string{"self-hosted-dns"}) {
		t.Errorf("the domain record with OWASP's name server = %+v", dr)
	}
}

func TestWidelySharedTokensDoNotCount(t *testing.T) {
	g := signalsFixture()
	for i := 0; i <= lens.GapMaxShared; i++ {
		id := fmt.Sprintf("tenant%d.example", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: id, Content: map[string]any{"name": id}}
		g.EvidenceByID[id] = []graph.Evidence{graphtest.TXTRecord("google-site-verification=owasp-token")}
	}

	c := candidateByID(signalsReport(t, g), "owasp-arts.org")
	if c == nil || slices.Contains(signalIDs(c), "txt-verification-token") {
		t.Errorf("a token on %d domains still counted: %+v", lens.GapMaxShared+1, c)
	}
}

func TestValueSignalsNeedAValueSearcher(t *testing.T) {
	g := signalsFixture()
	r := signalsReport(t, g.VendorGraph)
	if c := candidateByID(r, "owasp-arts.org"); c != nil {
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
		if q.AssetID == "owasp-arts.org" {
			p = &q
		}
	}
	if p == nil {
		t.Fatal("no proposal for owasp-arts.org's contact")
	}

	text := review.FormatOwnershipEntries([]review.OwnershipEntry{{Proposal: *p, Status: review.ProposalPending}})
	for _, want := range []string{"why: Shared DNS verification token (strong):",
		"why: Email authentication delegated to the organization (strong):"} {
		if !strings.Contains(text, want) {
			t.Errorf("listing lacks %q:\n%s", want, text)
		}
	}
	if f := OwnershipFeatures(*p); f["signal:txt-verification-token"] != 1 {
		t.Errorf("features = %v", f)
	}
}

// Live review: an unrelated domain (utica.edu here) shared an issuing key with calendar.owasp.org
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

	add("cert-cal", "calendar.owasp.org", "WE1")
	add("we1", "WE1", "GTS Root R4")
	link("cert-cal", "common_name", "portal.owasp.org")
	link("cert-cal", "issuing_certificate", "we1")
	add("cert-utica", "utica.edu", "WE1")
	g.Assets["utica.edu"] = graph.Asset{ID: "utica.edu", Type: "FQDN", Key: "utica.edu",
		Content: map[string]any{"name": "utica.edu"}}
	link("cert-utica", "common_name", "utica.edu")

	if c := candidateByID(signalsReport(t, g), "utica.edu"); c != nil {
		t.Errorf("a certificate from a public intermediate counted as a private CA: %+v", c)
	}
}

func TestNamesUnderOwnedDomainsAreOwned(t *testing.T) {
	g := signalsFixture()
	g.Assets["csvm02"] = graph.Asset{ID: "csvm02", Type: "FQDN", Key: "csvm02.owasp.org",
		Content: map[string]any{"name": "csvm02.owasp.org"}}
	g.Links = append(g.Links, graph.Relation{ID: "csvm02-dns", FromID: "csvm02", ToID: "ip-own", Label: "dns_record",
		Type: "BasicDNSRelation"})

	if c := candidateByID(signalsReport(t, g), "csvm02"); c != nil {
		t.Errorf("a name under owasp.org became a candidate: %+v", c)
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

	// OWASP's controlled registration contact has a custom-domain mailbox
	// and a free-webmail one.
	email("email:admin@owasp.org", "admin@owasp.org")
	email("email:owasp.alumni@gmail.com", "owasp.alumni@gmail.com")
	link("cr-owasp", "id", "email:admin@owasp.org")
	link("cr-owasp", "id", "email:owasp.alumni@gmail.com")

	// An unowned domain registered with a different mailbox at owasp.org,
	// and one sharing only the gmail.com webmail domain.
	sibling("owasp-labs.org", "cr-labs", "email:webmaster@owasp.org", "webmaster@owasp.org")
	sibling("free.example", "cr-free", "email:someone@gmail.com", "someone@gmail.com")

	r := signalsReport(t, g)

	c := candidateByID(r, "cr-labs")
	if c == nil {
		t.Fatalf("cr-labs is not a candidate: %+v", r.Candidates)
	}
	if !slices.Contains(signalIDs(c), "shared-registrant-email-domain") {
		t.Errorf("cr-labs signals = %v, want shared-registrant-email-domain", signalIDs(c))
	}
	// One strong signal alone waits for review, and it attaches to the subject.
	if c.Decision != lens.GapReview || c.Attachment == nil ||
		c.Attachment.String() != "ContactRecord https://rdap.example/cr-labs --organization--> Organization OWASP Foundation" {
		t.Errorf("decision %s, attachment %v", c.Decision, c.Attachment)
	}

	// A shared free-webmail domain identifies no owner, so it gives no signal.
	if fc := candidateByID(r, "cr-free"); fc != nil && slices.Contains(signalIDs(fc), "shared-registrant-email-domain") {
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

	// OWASP's controlled network registration has its own operations contact
	// at a custom mail domain.
	add("cr-netops", "ContactRecord", "https://rdap.example/netops", nil)
	email("email:noc@owasp-net.example", "noc@owasp-net.example")
	link("ipnet-own", "registrant", "cr-netops")
	link("cr-netops", "id", "email:noc@owasp-net.example")

	// An unowned domain registered with a different mailbox at that same mail
	// domain: the same operator, found across network and domain registration.
	add("partner.example", "FQDN", "partner.example", map[string]any{"name": "partner.example"})
	add("dr-partner", "DomainRecord", "partner.example", map[string]any{"domain": "partner.example"})
	add("cr-partner", "ContactRecord", "https://rdap.example/partner", nil)
	email("email:admin@owasp-net.example", "admin@owasp-net.example")
	link("partner.example", "registration", "dr-partner")
	link("dr-partner", "registrant_contact", "cr-partner")
	link("cr-partner", "id", "email:admin@owasp-net.example")

	r := signalsReport(t, g)
	c := candidateByID(r, "cr-partner")
	if c == nil {
		t.Fatalf("cr-partner is not a candidate: %+v", r.Candidates)
	}
	if !slices.Contains(signalIDs(c), "shared-registrant-email-domain") {
		t.Errorf("cr-partner signals = %v, want shared-registrant-email-domain", signalIDs(c))
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

	// OWASP's controlled apex publishes a DKIM key under a selector.
	fqdn("sel._domainkey.owasp.org")
	link("owasp.org", "node", "sel._domainkey.owasp.org")
	g.EvidenceByID["sel._domainkey.owasp.org"] = []graph.Evidence{graphtest.TXTRecord(txt)}

	// An unowned domain publishes the same DKIM key under its own selector.
	fqdn("owasp-mail.org")
	add("dr-mail", "DomainRecord", "owasp-mail.org", map[string]any{"domain": "owasp-mail.org"})
	add("cr-mail", "ContactRecord", "https://rdap.example/mail", nil)
	fqdn("default._domainkey.owasp-mail.org")
	link("owasp-mail.org", "registration", "dr-mail")
	link("dr-mail", "registrant_contact", "cr-mail")
	link("owasp-mail.org", "node", "default._domainkey.owasp-mail.org")
	g.EvidenceByID["default._domainkey.owasp-mail.org"] = []graph.Evidence{graphtest.TXTRecord(txt)}

	r := signalsReport(t, g)
	c := candidateByID(r, "owasp-mail.org")
	if c == nil {
		t.Fatalf("owasp-mail.org is not a candidate: %+v", r.Candidates)
	}
	if !slices.Contains(signalIDs(c), "dkim-key-reuse") {
		t.Errorf("owasp-mail.org signals = %v, want dkim-key-reuse", signalIDs(c))
	}
}

// TestSecurityTxtReferenceSignal: an unowned name whose security.txt points a
// URL, or its security contact, into the organization's namespace is linked
// by the security-txt-reference signal.
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

	// secTxt stores a security.txt for host: its URL, joined to the host, and
	// the file's ContactRecord.
	secTxt := func(host string) string {
		file, cr := "file-"+host, "cr-"+host
		add(file, "URL", map[string]any{"url": "https://" + host + "/.well-known/security.txt", "host": host,
			"path": "/.well-known/security.txt"})
		add(cr, "ContactRecord", map[string]any{"discovered_at": "https://" + host + "/.well-known/security.txt"})
		link(file, "domain", host, "SimpleRelation")
		link(file, "contact", cr, "SimpleRelation")
		return cr
	}

	// An unowned site whose security.txt canonical URL is in owasp.org.
	fqdn("partner-run.example")
	add("url-canon", "URL", map[string]any{"url": "https://owasp.org/.well-known/security.txt",
		"host": "owasp.org"})
	link(secTxt("partner-run.example"), "url", "url-canon", "SimpleRelation")

	// An unowned site whose security contact is a mailbox at owasp.org.
	fqdn("vendor-site.example")
	add("id-b", "Identifier", map[string]any{"id": "security@owasp.org", "id_type": "email"})
	link(secTxt("vendor-site.example"), "id", "id-b", "SimpleRelation")

	r := signalsReport(t, g)
	for _, id := range []string{"partner-run.example", "vendor-site.example"} {
		c := candidateByID(r, id)
		if c == nil {
			t.Errorf("%s is not a candidate: %+v", id, r.Candidates)
			continue
		}
		if !slices.Contains(signalIDs(c), "security-txt-reference") {
			t.Errorf("%s signals = %v, want security-txt-reference", id, signalIDs(c))
		}
	}
}
