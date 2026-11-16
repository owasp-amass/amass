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
		g.Links = append(g.Links, graph.Relation{ID: "colgate.edu-node-" + id, FromID: "colgate.edu", ToID: id,
			Label: "node", Type: "SimpleRelation"})
	}
	if g.EvidenceByID == nil {
		g.EvidenceByID = map[string][]graph.Evidence{}
	}
	add("weak._domainkey.colgate.edu")
	add("old._domainkey.colgate.edu")
	g.EvidenceByID["weak._domainkey.colgate.edu"] = []graph.Evidence{graphtest.TXTRecord(rsaDKIM(t, 512))}
	g.EvidenceByID["old._domainkey.colgate.edu"] = []graph.Evidence{graphtest.TXTRecord("v=DKIM1; k=rsa; p=")}

	r, err := FindEmailSecurity(context.Background(), g,
		graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["colgate.edu"], LensLimits{})
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
		if r.Domains[i].Domain == "colgate.edu" {
			dom = &r.Domains[i]
		}
	}
	if dom == nil || !slices.ContainsFunc(dom.DKIMWeak, func(s string) bool { return strings.Contains(s, "512-bit") }) {
		t.Errorf("colgate.edu DKIMWeak = %v", dom)
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
