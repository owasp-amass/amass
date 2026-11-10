// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// valueGraph adds value searches to the campus fixture, over stored TXT
// records (evidence) and asset content.
type valueGraph struct{ vendorGraph }

func (g valueGraph) FindByTagValue(_ context.Context, assetType, name, value string, contains bool,
	limit int) ([]Asset, bool, error) {
	var out []Asset
	for id, evs := range g.evidence {
		a, ok := g.assets[id]
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

	slices.SortFunc(out, func(a, b Asset) int { return strings.Compare(a.ID, b.ID) })
	if len(out) > limit {
		return out[:limit], true, nil
	}

	return out, false, nil
}

func (g valueGraph) FindByAttribute(_ context.Context, assetType, key, value string, contains bool,
	limit int) ([]Asset, bool, error) {
	var out []Asset
	for _, a := range g.assets {
		if a.Type != assetType {
			continue
		}

		text := contentString(a, key)
		if !contains && text == value {
			out = append(out, a)
		} else if contains {
			data, _ := json.Marshal(contentValue(a, key))
			if strings.Contains(strings.ToLower(string(data)), strings.ToLower(value)) {
				out = append(out, a)
			}
		}
	}

	slices.SortFunc(out, func(a, b Asset) int { return strings.Compare(a.ID, b.ID) })
	if len(out) > limit {
		return out[:limit], true, nil
	}

	return out, false, nil
}

func txtRecord(data string) Evidence {
	return Evidence{Kind: "DNSRecordProperty", Property: map[string]any{"property_name": "dns_record",
		"header": map[string]any{"rr_type": rrTypeTXT, "class": 1}, "data": data}}
}

// signalsFixture extends the campus with evidence for each value signal:
//   - colgate-arts.org shares Colgate's site verification token and
//     includes Colgate's SPF;
//   - colgate-news.org sends DMARC reports to colgate.edu;
//   - colgate-portal.net has a certificate with the key and private issuer
//     of Colgate's certificate;
//   - hamco.org uses Colgate's name server.
func signalsFixture() valueGraph {
	g := valueGraph{campusGapsFixture()}
	g.evidence = map[string][]Evidence{}
	add := func(id, typ, key string, content map[string]any) {
		g.assets[id] = Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	named := func(id, typ, name string) { add(id, typ, name, map[string]any{"name": name}) }
	link := func(from, label, to, rt string, content any) {
		g.links = append(g.links, Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt, Content: content})
	}
	registered := func(domain string) {
		named(domain, "FQDN", domain)
		add("dr-"+domain, "DomainRecord", domain, map[string]any{"domain": domain})
		add("cr-"+domain, "ContactRecord", "https://rdap.example/"+domain, nil)
		link(domain, "registration", "dr-"+domain, "SimpleRelation", nil)
		link("dr-"+domain, "registrant_contact", "cr-"+domain, "SimpleRelation", nil)
	}

	g.evidence["colgate.edu"] = []Evidence{txtRecord("google-site-verification=colgate-token"),
		txtRecord("v=spf1 include:_spf.google.com ~all")}

	registered("colgate-arts.org")
	g.evidence["colgate-arts.org"] = []Evidence{txtRecord("google-site-verification=colgate-token"),
		txtRecord("v=spf1 include:_spf.colgate.edu ~all")}

	registered("colgate-news.org")
	named("_dmarc.colgate-news.org", "FQDN", "_dmarc.colgate-news.org")
	link("colgate-news.org", "node", "_dmarc.colgate-news.org", "SimpleRelation", nil)
	g.evidence["_dmarc.colgate-news.org"] = []Evidence{txtRecord("v=DMARC1; p=none; rua=mailto:dmarc@colgate.edu")}

	// A look-alike that only contains the name never counts.
	registered("notcolgate.edu.example")
	g.evidence["notcolgate.edu.example"] = []Evidence{txtRecord("v=spf1 include:mail.notcolgate.edu ~all")}

	g.assets["cert"] = Asset{ID: "cert", Type: "TLSCertificate", Key: "1234", Content: map[string]any{
		"serial_number": "1234", "subject_key_id": "aa:bb", "authority_key_id": "ca:01",
		"issuer_common_name": "Colgate Internal CA"}}
	link("cert", "common_name", "www.colgate.edu", "SimpleRelation", nil)
	add("cert-portal", "TLSCertificate", "5678", map[string]any{"serial_number": "5678", "subject_key_id": "aa:bb",
		"authority_key_id": "ca:01", "issuer_common_name": "Colgate Internal CA"})
	registered("colgate-portal.net")
	link("cert-portal", "common_name", "colgate-portal.net", "SimpleRelation", nil)

	link("colgate.edu", "node", "ns1.colgate.edu", "SimpleRelation", nil)
	registered("hamco.org")
	link("dr-hamco.org", "name_server", "ns1.colgate.edu", "SimpleRelation", nil)
	link("hamco.org", "dns_record", "ns1.colgate.edu", "BasicDNSRelation",
		map[string]any{"header": map[string]any{"rr_type": rrTypeNS}})
	return g
}

func signalsReport(t *testing.T, g Graph) OwnershipGapReport {
	t.Helper()

	r, err := searchOwnershipGaps(context.Background(), g, vendorCatalog{testOAMCatalog}, Asset{ID: "colgate",
		Type: "Organization", Key: "Colgate University", Content: map[string]any{"name": "Colgate University"}})
	if err != nil {
		t.Fatal(err)
	}

	return r
}

// candidateByID finds a candidate by asset ID; a domain record and its
// name share a label.
func candidateByID(r OwnershipGapReport, id string) *GapCandidate {
	for i, c := range r.Candidates {
		if c.AssetID == id {
			return &r.Candidates[i]
		}
	}

	return nil
}

func signalIDs(c *GapCandidate) []string {
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
	if c.Decision != GapPropose || c.Attachment == nil ||
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
		c.Decision != GapReview {
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
	if c.Decision != GapPropose {
		t.Errorf("decision = %s", c.Decision)
	}
}

func TestPublicIssuersAreNotPrivateCAs(t *testing.T) {
	g := signalsFixture()
	for _, id := range []string{"cert", "cert-portal"} {
		a := g.assets[id]
		a.Content.(map[string]any)["issuer_common_name"] = "R3"
		a.Content.(map[string]any)["subject_key_id"] = "key-" + id
		g.assets[id] = a
	}

	if c := candidateByID(signalsReport(t, g), "colgate-portal.net"); c != nil {
		t.Errorf("a public issuer linked certificates: %+v", c)
	}
	for _, tc := range []struct {
		issuer string
		public bool
	}{{"R3", true}, {"Let's Encrypt Authority X3", true}, {"Partner3 Root", false}, {"Colgate Internal CA", false},
		{"DigiCert Global G2 TLS RSA SHA256 2020 CA1", true}} {
		def, _ := ownershipSignal("private_ca_issuance")
		if got := publicIssuer(tc.issuer, def.Params.PublicIssuers); got != tc.public {
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
	for i := 0; i <= gapMaxShared; i++ {
		id := fmt.Sprintf("tenant%d.example", i)
		g.assets[id] = Asset{ID: id, Type: "FQDN", Key: id, Content: map[string]any{"name": id}}
		g.evidence[id] = []Evidence{txtRecord("google-site-verification=colgate-token")}
	}

	c := candidateByID(signalsReport(t, g), "colgate-arts.org")
	if c == nil || slices.Contains(signalIDs(c), "txt_verification_token") {
		t.Errorf("a token on %d domains still counted: %+v", gapMaxShared+1, c)
	}
}

func TestValueSignalsNeedAValueSearcher(t *testing.T) {
	g := signalsFixture()
	r := signalsReport(t, g.vendorGraph)
	if c := candidateByID(r, "colgate-arts.org"); c != nil {
		t.Errorf("value signals ran without value searches: %+v", c)
	}
	if c := candidateByID(r, "hamco.org"); c == nil {
		t.Error("relationship signals stopped without value searches")
	}
}

func TestDelegatesTo(t *testing.T) {
	cases := map[string]string{
		"v=spf1 include:_spf.example.com ~all":                        "include:_spf.example.com",
		"v=spf1 ip4:192.0.2.0/24 redirect=example.com":                "redirect:example.com",
		"v=spf1 +include:example.com -all":                            "include:example.com",
		"v=spf1 include:notexample.com ~all":                          "",
		"v=DMARC1; p=reject; rua=mailto:d@example.com,mailto:x@y.org": "rua:example.com",
		"v=DMARC1; p=none; ruf=mailto:f@reports.example.com!10m":      "ruf:reports.example.com",
		"v=DMARC1; p=none; rua=mailto:d@vendor.example":               "",
		"google-site-verification=example.com":                        "",
	}
	for txt, want := range cases {
		if got := delegatesTo(txt, "example.com"); got != want {
			t.Errorf("delegatesTo(%q) = %q, want %q", txt, got, want)
		}
	}
}

func TestSignalCatalogIsValid(t *testing.T) {
	signals := OwnershipSignals()
	if len(signals) < 8 {
		t.Fatalf("catalog has %d signals", len(signals))
	}
	for _, s := range signals {
		if len(s.Guards) == 0 || len(s.CounterIndications) == 0 {
			t.Errorf("signal %s documents no guards or counter-indications", s.ID)
		}
	}
	for _, id := range []string{sigSharedRegistrant, sigHosting, sigColisting, sigSelfHostedDNS} {
		if _, ok := ownershipSignal(id); !ok {
			t.Errorf("signal %s used in code is missing from the catalog", id)
		}
	}
	if err := validateSignals(append(slices.Clone(signals), signals[0])); err == nil {
		t.Error("a repeated signal id was accepted")
	}
}

// TestSignalsDocIsCurrent keeps docs/ai/SIGNALS.md generated from the
// catalog. Regenerate it with AMASS_UPDATE_SIGNALS_DOC=1 go test -run
// TestSignalsDocIsCurrent ./internal/ai/.
func TestSignalsDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "ai", "SIGNALS.md")
	want := SignalsMarkdown()
	if os.Getenv("AMASS_UPDATE_SIGNALS_DOC") != "" {
		if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Error("docs/ai/SIGNALS.md is out of date; regenerate it with AMASS_UPDATE_SIGNALS_DOC=1 go test -run " +
			"TestSignalsDocIsCurrent ./internal/ai/")
	}
}

func TestProposalsExplainTheirSignals(t *testing.T) {
	r := signalsReport(t, signalsFixture())
	var p *OwnershipProposal
	for _, q := range OwnershipProposals(r) {
		if q.AssetID == "colgate-arts.org" {
			p = &q
		}
	}
	if p == nil {
		t.Fatal("no proposal for colgate-arts.org's contact")
	}

	text := FormatOwnershipEntries([]OwnershipEntry{{Proposal: *p, Status: ProposalPending}})
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
