// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

func TestParseRealm(t *testing.T) {
	body := `<RealmInfo Success="true"><NameSpaceType>Federated</NameSpaceType>` +
		`<FederationBrandName>Utica Products &amp; Co</FederationBrandName>` +
		`<AuthURL>https://STS.utica-products.example/adfs/ls/?username=admin%40utica-products.example&amp;wa=wsignin1.0</AuthURL>` +
		`</RealmInfo>`
	r := parseRealm(body)
	if r.namespace != "federated" || r.brand != "Utica Products & Co" || r.authHost != "sts.utica-products.example" {
		t.Errorf("realm = %+v", r)
	}
	if r := parseRealm(`<RealmInfo><NameSpaceType>Unknown</NameSpaceType><AuthURL>https://x.example/</AuthURL></RealmInfo>`); r != (realm{}) {
		t.Errorf("an unknown namespace kept %+v", r)
	}
	if r := parseRealm(`<RealmInfo><NameSpaceType>Managed</NameSpaceType></RealmInfo>`); r.namespace != "managed" ||
		r.authHost != "" {
		t.Errorf("a managed realm = %+v", r)
	}
}

func TestIssuerHost(t *testing.T) {
	for body, want := range map[string]string{
		`{"issuer":"https://Utica-Products.okta.com/oauth2/default","jwks_uri":"x"}`: "utica-products.okta.com",
		`{"issuer":"https://login.owasp.org"}`:                                       "login.owasp.org",
		`{"issuer":"http://login.owasp.org"}`:                                        "",
		`{"issuer":"https://localhost:8443/"}`:                                       "",
		`<html>not found</html>`:                                                     "",
		``:                                                                           "",
	} {
		if got := issuerHost(body); got != want {
			t.Errorf("issuerHost(%s) = %q, want %q", body, got, want)
		}
	}
}

// selfSigned returns a base64 DER certificate for cn.
func selfSigned(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// Signing and unmarked key descriptors count, encryption ones and
// duplicates do not, and wrapped base64 is read.
func TestMetadataSigningCerts(t *testing.T) {
	sign, both, enc := selfSigned(t, "ADFS Signing - sts.owasp.org"), selfSigned(t, "both"), selfSigned(t, "enc")
	wrapped := sign[:40] + "\n      " + sign[40:]
	body := `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata"><RoleDescriptor>` +
		`<KeyDescriptor use="encryption"><KeyInfo><X509Data><X509Certificate>` + enc + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<KeyDescriptor use="signing"><ds:KeyInfo><ds:X509Data><ds:X509Certificate>` + wrapped + `</ds:X509Certificate></ds:X509Data></ds:KeyInfo></KeyDescriptor>` +
		`<KeyDescriptor><KeyInfo><X509Data><X509Certificate>` + both + `</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`<KeyDescriptor use='signing'><KeyInfo><X509Data><X509Certificate>` + sign + `</X509Certificate><X509Certificate>bm90IGEgY2VydA==</X509Certificate></X509Data></KeyInfo></KeyDescriptor>` +
		`</RoleDescriptor></EntityDescriptor>`
	got := metadataSigningCerts(body)
	if len(got) != 2 || got[0].Subject.CommonName != "ADFS Signing - sts.owasp.org" || got[1].Subject.CommonName != "both" {
		names := make([]string, len(got))
		for i, c := range got {
			names[i] = c.Subject.CommonName
		}
		t.Errorf("signing certificates = %s", strings.Join(names, ", "))
	}
	if len(metadataSigningCerts("<html></html>")) != 0 {
		t.Error("a page with no metadata gave certificates")
	}
}

func TestAskedHosts(t *testing.T) {
	var a askedHosts
	limit := semantics.IdentityProviderCatalog().MaxHosts
	for i := 0; i < limit; i++ {
		if !a.take("s1", "owasp.org") {
			t.Fatalf("name %d was refused", i+1)
		}
	}
	if a.take("s1", "owasp.org") || !a.take("s2", "owasp.org") || !a.take("s1", "utica.edu") {
		t.Error("the per-session, per-domain limit is wrong")
	}
	if !a.first("s1", "owasp.okta.com") || a.first("s1", "owasp.okta.com") || !a.first("s2", "owasp.okta.com") {
		t.Error("a provider host is not asked once per session")
	}
}
