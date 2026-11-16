// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"math/big"
	"testing"
)

func TestPublicKeySHA256(t *testing.T) {
	spki := []byte("example SubjectPublicKeyInfo DER bytes")
	sum := sha256.Sum256(spki)
	want := hex.EncodeToString(sum[:])

	if got := publicKeySHA256(&x509.Certificate{RawSubjectPublicKeyInfo: spki}); got != want {
		t.Errorf("publicKeySHA256 = %s, want %s", got, want)
	}

	// A certificate with no stored key info yields an empty hash, not a hash
	// of nothing.
	if got := publicKeySHA256(&x509.Certificate{}); got != "" {
		t.Errorf("empty SubjectPublicKeyInfo should yield an empty hash, got %q", got)
	}
}

func TestX509ToOAMTLSCertificateSetsPublicKeyHash(t *testing.T) {
	spki := []byte("another public key")
	sum := sha256.Sum256(spki)
	want := hex.EncodeToString(sum[:])

	c := X509ToOAMTLSCertificate(&x509.Certificate{
		Version:                 3,
		SerialNumber:            big.NewInt(1),
		RawSubjectPublicKeyInfo: spki,
	})
	if c == nil {
		t.Fatal("conversion returned nil")
	}
	if c.PublicKeySHA256 != want {
		t.Errorf("PublicKeySHA256 = %q, want %q", c.PublicKeySHA256, want)
	}
}
