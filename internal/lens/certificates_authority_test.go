// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import "testing"

// One authority is counted once however a certificate names it: by its
// organization or by the common name of the issuing certificate.
func TestCertificateAuthority(t *testing.T) {
	for issuer, want := range map[string]string{
		"amazon":                            "Amazon",
		"Amazon RSA 2048 M04":               "Amazon",
		"R10":                               "Let's Encrypt",
		"Let's Encrypt Authority X3":        "Let's Encrypt",
		"WR2":                               "Google Trust Services",
		"DigiCert Global G2 TLS RSA SHA256": "DigiCert",
		"GeoTrust TLS RSA CA G1":            "DigiCert",
		"Sectigo RSA Domain Validation":     "Sectigo",
	} {
		if got, ok := CertificateAuthority(issuer); !ok || got != want {
			t.Errorf("CertificateAuthority(%q) = %q, %t; want %q", issuer, got, ok, want)
		}
	}

	// A private CA and a short name that only looks like an intermediate are
	// no public authority.
	for _, issuer := range []string{"OWASP Internal CA", "Partner3 Root", "R2D2 Lab CA", ""} {
		if got, ok := CertificateAuthority(issuer); ok {
			t.Errorf("CertificateAuthority(%q) = %q; want no authority", issuer, got)
		}
	}
}
