// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bimi

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
)

func TestParseBIMI(t *testing.T) {
	r, ok := parseBIMI("v=BIMI1; l=https://example.com/logo.svg; a=https://example.com/vmc.pem")
	if !ok || r.logo != "https://example.com/logo.svg" || r.evidence != "https://example.com/vmc.pem" {
		t.Fatalf("parseBIMI = %+v, %v", r, ok)
	}
	if _, ok := parseBIMI("v=spf1 -all"); ok {
		t.Fatal("a non-BIMI record parsed")
	}
	if r, ok := parseBIMI("v=BIMI1; l=; a=;"); !ok || r.evidence != "" {
		t.Fatalf("declination record = %+v, %v", r, ok)
	}
}

func testMarkCert(t *testing.T, names []string, eku []asn1.ObjectIdentifier, notAfter time.Time) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(4242),
		Subject: pkix.Name{
			Organization: []string{"Example Corp"},
			ExtraNames: []pkix.AttributeTypeAndValue{
				{Type: oidTrademarkOffice, Value: "USPTO"},
				{Type: oidTrademarkCountry, Value: "us"},
				{Type: oidTrademarkID, Value: "1234567"},
				{Type: oidLEI, Value: "5493001kjtiigc8y1r12"},
				{Type: oidWordMark, Value: "EXAMPLE"},
				{Type: oidMarkType, Value: "Registered Mark"},
			},
		},
		DNSNames:           names,
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           notAfter,
		UnknownExtKeyUsage: eku,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestMarkCertificate(t *testing.T) {
	now := time.Now()
	later := now.Add(24 * time.Hour)
	bimi := []asn1.ObjectIdentifier{support.OIDBIMIKeyUsage}

	good := testMarkCert(t, []string{"example.com"}, bimi, later)
	cert := markCertificate(good, "example.com", now)
	if cert == nil {
		t.Fatal("the mark certificate was not found")
	}

	d := subjectDetails(cert)
	want := markDetails{office: "USPTO", country: "US", trademark: "1234567",
		lei: "5493001KJTIIGC8Y1R12", wordMark: "EXAMPLE", markType: "Registered Mark"}
	if d != want {
		t.Fatalf("subjectDetails = %+v, want %+v", d, want)
	}
	if k := support.X509ContactKey(cert, "Subject"); k != "x509 Certificate: 4242, Subject" {
		t.Fatalf("X509ContactKey = %q", k)
	}

	cases := map[string][]byte{
		"other domain":    testMarkCert(t, []string{"other.com"}, bimi, later),
		"no BIMI usage":   testMarkCert(t, []string{"example.com"}, nil, later),
		"expired":         testMarkCert(t, []string{"example.com"}, bimi, now.Add(-time.Minute)),
		"not a PEM block": []byte("not a certificate"),
	}
	for name, data := range cases {
		if markCertificate(data, "example.com", now) != nil {
			t.Errorf("%s: a certificate was accepted", name)
		}
	}

	// The mark certificate is found after an issuing certificate in the chain.
	chain := append(testMarkCert(t, nil, nil, later), good...)
	if markCertificate(chain, "EXAMPLE.com", now) == nil {
		t.Fatal("the mark certificate was not found in a chain")
	}
}
