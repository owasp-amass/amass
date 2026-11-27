// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// rsaDKIM returns a DKIM TXT record carrying an RSA public key of the given
// size. Go refuses to generate keys under 1024 bits, so a small modulus is
// built by hand — which also confirms the lens can parse the very weak keys
// it flags.
func rsaDKIM(t *testing.T, bits int) string {
	t.Helper()

	var der []byte
	var err error
	if bits >= 1024 {
		key, kerr := rsa.GenerateKey(rand.Reader, bits)
		if kerr != nil {
			t.Fatal(kerr)
		}
		der, err = x509.MarshalPKIXPublicKey(&key.PublicKey)
	} else {
		n := new(big.Int).Lsh(big.NewInt(1), uint(bits-1))
		n.SetBit(n, 0, 1)
		der, err = x509.MarshalPKIXPublicKey(&rsa.PublicKey{N: n, E: 65537})
	}
	if err != nil {
		t.Fatal(err)
	}
	return "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(der)
}

func TestDKIMKeyHealth(t *testing.T) {
	if s, bits := dkimKeyHealth(rsaDKIM(t, 512)); s != "weak" || bits != 512 {
		t.Errorf("512-bit RSA = (%q, %d), want (weak, 512)", s, bits)
	}
	if s, _ := dkimKeyHealth(rsaDKIM(t, 2048)); s != "" {
		t.Errorf("2048-bit RSA = %q, want ok", s)
	}
	if s, _ := dkimKeyHealth("v=DKIM1; k=rsa; p="); s != "revoked" {
		t.Errorf("empty p= = %q, want revoked", s)
	}
	// An ed25519 key is short but strong, so it is not flagged.
	if s, _ := dkimKeyHealth("v=DKIM1; k=ed25519; p=11qYAYKxCrfVS/7TyWQHOg7hcvPapiMlrwIaaPcHURo="); s != "" {
		t.Errorf("ed25519 = %q, want ok", s)
	}
	// A record that is not DKIM, or an unparseable key, is not flagged.
	if s, _ := dkimKeyHealth("v=spf1 -all"); s != "" {
		t.Errorf("non-DKIM = %q, want ok", s)
	}
}

func TestFindEmailSecurityFlagsWeakDKIM(t *testing.T) {
	g := graphtest.VendorFixture()
	add := func(id string) {
		g.Assets[id] = graph.Asset{ID: id, Type: "FQDN", Key: id, Content: map[string]any{"name": id}}
		g.Links = append(g.Links, graph.Relation{ID: "owasp.org-node-" + id, FromID: "owasp.org", ToID: id,
			Label: "node", Type: "SimpleRelation"})
	}
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	add("weak._domainkey.owasp.org")
	add("old._domainkey.owasp.org")
	g.EvidenceByID["weak._domainkey.owasp.org"] = []graph.Evidence{graphtest.TXTRecord(rsaDKIM(t, 512))}
	g.EvidenceByID["old._domainkey.owasp.org"] = []graph.Evidence{graphtest.TXTRecord("v=DKIM1; k=rsa; p=")}

	r, err := FindEmailSecurity(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}

	kinds := map[string]bool{}
	for _, f := range r.Findings {
		kinds[f.Kind] = true
	}
	if !kinds[EmailDKIMWeak] || !kinds[EmailDKIMRevoked] {
		t.Errorf("findings = %v, want weak and revoked DKIM", r.Findings)
	}

	var dom *MailDomain
	for i := range r.Domains {
		if r.Domains[i].Domain == "owasp.org" {
			dom = &r.Domains[i]
		}
	}
	if dom == nil || !slices.ContainsFunc(dom.DKIMWeak, func(s string) bool { return strings.Contains(s, "512-bit") }) {
		t.Errorf("owasp.org DKIMWeak = %v", dom)
	}
}

// MX hosts are named by the provider that documents them, and a host no
// provider documents is left for the vendor names.
func TestMailProviderOf(t *testing.T) {
	rules := loadEmailRules()
	for host, want := range map[string]string{
		"smtp.google.com":                         "Google Workspace",
		"ASPMX.L.GOOGLE.COM.":                     "Google Workspace",
		"example-com.mail.protection.outlook.com": "Microsoft 365",
		"mx1.us2.ppe-hosted.com":                  "Proofpoint Essentials",
		"us-smtp-inbound-1.mimecast.com":          "Mimecast",
		"d123456a.ess.barracudanetworks.com":      "Barracuda Email Security Service",
		"mx1.example.iphmx.com":                   "Cisco Secure Email Cloud Gateway",
		"mx1.example.eu.iphmx.com":                "Cisco Secure Email Cloud Gateway",
		"mail.example.com":                        "",
		"google.com.example.net":                  "",
		"mail.protection.outlook.com.example.org": "",
	} {
		if got := mailProviderOf(rules, host); got != want {
			t.Errorf("mailProviderOf(%q) = %q, want %q", host, got, want)
		}
	}
	for _, p := range rules.MailProviders {
		if !strings.HasPrefix(p.Source, "https://") {
			t.Errorf("mail provider %s cites no documentation", p.Provider)
		}
	}
}

func TestSPFLookupCount(t *testing.T) {
	cases := map[string]int{
		"v=spf1 -all":                                        0,
		"v=spf1 ip4:192.0.2.0/24 -all":                       0,
		"v=spf1 a mx include:a.com ~all":                     3,
		"v=spf1 include:a.com redirect=b.com":                2,
		"v=spf1 a:x.com mx:y.com ptr exists:%{i}.z.com -all": 4,
	}
	for spf, want := range cases {
		if got := spfLookupCount(spf); got != want {
			t.Errorf("spfLookupCount(%q) = %d, want %d", spf, got, want)
		}
	}
}

func TestFindEmailSecurityFlagsSPFLookupLimit(t *testing.T) {
	g := graphtest.VendorFixture()
	var b strings.Builder
	b.WriteString("v=spf1")
	for i := 0; i < 11; i++ {
		fmt.Fprintf(&b, " include:spf%d.example", i)
	}
	b.WriteString(" ~all")
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	g.EvidenceByID["owasp.org"] = []graph.Evidence{graphtest.TXTRecord(b.String())}

	r, err := FindEmailSecurity(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(r.Findings, func(f EmailFinding) bool { return f.Kind == EmailSPFManyLookups }) {
		t.Errorf("findings = %v, want spf_too_many_lookups", r.Findings)
	}
}

func TestFindEmailSecurityFlagsMTASTSTesting(t *testing.T) {
	g := graphtest.VendorFixture()
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	// The mta-sts.<domain> host and its HTTPS service, with the policy's mode
	// recorded as a service property.
	g.Assets["mta-sts.owasp.org"] = graph.Asset{ID: "mta-sts.owasp.org", Type: "FQDN",
		Key: "mta-sts.owasp.org", Content: map[string]any{"name": "mta-sts.owasp.org"}}
	g.Assets["svc-mtasts"] = graph.Asset{ID: "svc-mtasts", Type: "Service", Key: "svc-mtasts",
		Content: map[string]any{"service_type": "web-service"}}
	g.Links = append(g.Links,
		graph.Relation{ID: "owasp.org-node-mta-sts", FromID: "owasp.org", ToID: "mta-sts.owasp.org",
			Label: "node", Type: "SimpleRelation"},
		graph.Relation{ID: "mta-sts-port-svc", FromID: "mta-sts.owasp.org", ToID: "svc-mtasts",
			Label: "port", Type: "PortRelation"})
	g.EvidenceByID["svc-mtasts"] = []graph.Evidence{{Property: map[string]any{
		"property_name": "mta_sts_mode", "property_value": "testing"}}}

	r, err := FindEmailSecurity(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp.org"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if !slices.ContainsFunc(r.Findings, func(f EmailFinding) bool { return f.Kind == EmailMTASTSTesting }) {
		t.Errorf("findings = %v, want mta_sts_not_enforced", r.Findings)
	}
}
