// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ocds

import (
	"bytes"
	"compress/gzip"
	"strings"
	"testing"
)

// A release package with the buyer named directly and two suppliers on one award.
const releasePackage = `{"releases":[
  {"ocid":"ocds-abc-001","date":"2023-05-01T00:00:00Z",
   "buyer":{"id":"b1","name":"Ministério da Saúde"},
   "awards":[
     {"id":"aw-1","date":"2023-05-10T00:00:00Z","value":{"amount":1250000,"currency":"BRL"},
      "suppliers":[{"id":"s1","name":"Acme Brasil Ltda"},{"id":"s2","name":"Beta SA"}]}
   ]}
]}`

// A record package with the buyer only in parties[].roles and an award date absent.
const recordPackage = `{"records":[
  {"compiledRelease":{"ocid":"ocds-xyz-9","date":"2022-09-01",
    "parties":[{"id":"p1","name":"Secretaría de Salud","roles":["buyer"]},
               {"id":"p2","name":"Gamma SA de CV","roles":["supplier"]}],
    "awards":[{"id":"aw-9","value":{"amount":500000,"currency":"MXN"},
               "suppliers":[{"id":"p2","name":"Gamma SA de CV"}]}]}}
]}`

func TestParseOCDSReleasePackage(t *testing.T) {
	aws, err := parseOCDS([]byte(releasePackage))
	if err != nil {
		t.Fatal(err)
	}
	if len(aws) != 2 { // one award, two suppliers
		t.Fatalf("awards = %d, want 2", len(aws))
	}
	if aws[0].supplier != "Acme Brasil Ltda" || aws[0].buyer != "Ministério da Saúde" ||
		aws[0].amount != 1250000 || aws[0].currency != "BRL" || aws[0].date != "2023-05-10T00:00:00Z" {
		t.Errorf("award0 = %+v", aws[0])
	}
}

func TestParseOCDSRecordPackage(t *testing.T) {
	aws, err := parseOCDS([]byte(recordPackage))
	if err != nil {
		t.Fatal(err)
	}
	if len(aws) != 1 {
		t.Fatalf("awards = %d, want 1", len(aws))
	}
	a := aws[0]
	// Buyer resolved from parties[].roles; award date falls back to the release date.
	if a.buyer != "Secretaría de Salud" || a.supplier != "Gamma SA de CV" || a.date != "2022-09-01" ||
		a.currency != "MXN" {
		t.Errorf("award = %+v", a)
	}
}

func TestSupplierMatches(t *testing.T) {
	if !supplierMatches("Acme Brasil Ltda", "ACME BRASIL LTDA") {
		t.Error("case-insensitive match expected")
	}
	if supplierMatches("Acme Brasil Ltda", "Acme Servicios SA") {
		t.Error("different entity should not match")
	}
}

func TestPublishersCatalogLoads(t *testing.T) {
	pubs := loadPublishers()
	if len(pubs) == 0 {
		t.Fatal("catalog is empty")
	}
	// Seed publishers are disabled until a supplier-search endpoint or a bulk
	// export is validated; an enabled one must have one or the other.
	for _, p := range pubs {
		if p.Enabled && !containsSupplier(p.QueryURL) && p.BulkURL == "" {
			t.Errorf("publisher %s is enabled but has neither a supplier query_url nor a bulk_url", p.Key)
		}
	}
}

func TestScanBulkGzippedJSONL(t *testing.T) {
	// Two compiled releases, one per line; only the first names our supplier.
	lines := []string{
		`{"ocid":"ocds-mx-1","date":"2024-03-01","parties":[{"id":"b","name":"Secretaría de Educación","roles":["buyer"]}],` +
			`"awards":[{"id":"a1","value":{"amount":750000,"currency":"MXN"},"suppliers":[{"id":"s","name":"Gamma SA de CV"}]}]}`,
		`{"ocid":"ocds-mx-2","date":"2024-04-01","buyer":{"name":"Otra Dependencia"},` +
			`"awards":[{"id":"a2","value":{"amount":10,"currency":"MXN"},"suppliers":[{"id":"x","name":"Unrelated Co"}]}]}`,
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	if _, err := gz.Write([]byte(strings.Join(lines, "\n") + "\n")); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}

	r, err := gzip.NewReader(&buf)
	if err != nil {
		t.Fatal(err)
	}
	var got []award
	trunc, err := scanBulk(r,
		func(s string) bool { return supplierMatches("Gamma SA de CV", s) },
		func(a award) { got = append(got, a) })
	if err != nil || trunc {
		t.Fatalf("scanBulk err=%v truncated=%v", err, trunc)
	}
	if len(got) != 1 {
		t.Fatalf("matched awards = %d, want 1 (only the matching supplier): %+v", len(got), got)
	}
	a := got[0]
	if a.ocid != "ocds-mx-1" || a.buyer != "Secretaría de Educación" || a.amount != 750000 || a.currency != "MXN" {
		t.Errorf("award = %+v", a)
	}
}

// TestScanBulkNuevoLeonShape checks a compiled release in the exact shape of
// the live Nuevo León (Mexico) bulk export validated for enabling: buyer named
// directly, the supplier also a tenderer party, an MX-RFC supplier id, MXN.
func TestScanBulkNuevoLeonShape(t *testing.T) {
	line := `{"ocid":"ocds-k3ufh7-291640","date":"2024-02-02T16:30:13Z","tag":["award"],` +
		`"buyer":{"name":"DIRECCIÓN DE FORMACIÓN CÍVICA"},` +
		`"parties":[{"name":"SECRETARÍA DE ADMINISTRACIÓN","roles":["procuringEntity"]},` +
		`{"name":"DIRECCIÓN DE FORMACIÓN CÍVICA","roles":["buyer"]},` +
		`{"name":"PROMOCIONES RAC, S.A. DE C.V.","roles":["tenderer","supplier"]}],` +
		`"awards":[{"id":"aw-1","date":"2024-02-02T16:29:23Z","value":{"amount":57640.4,"currency":"MXN"},` +
		`"suppliers":[{"name":"PROMOCIONES RAC, S.A. DE C.V.","id":"MX-RFC-PRA1205212M0"}]}]}`

	var got []award
	if _, err := scanBulk(strings.NewReader(line),
		func(s string) bool { return supplierMatches("PROMOCIONES RAC, S.A. DE C.V.", s) },
		func(a award) { got = append(got, a) }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("awards = %d, want 1", len(got))
	}
	a := got[0]
	if a.buyer != "DIRECCIÓN DE FORMACIÓN CÍVICA" || a.amount != 57640.4 || a.currency != "MXN" ||
		a.ocid != "ocds-k3ufh7-291640" {
		t.Errorf("award = %+v", a)
	}
}

// TestUKValueFallback checks the UK Find a Tender shape, where award.value is
// empty and the amount lives on the contract (linked by awardID) or, for a
// single-award process, at the tender level; an award with no value anywhere
// yields a zero amount (which store then skips).
func TestUKValueFallback(t *testing.T) {
	// A multi-award release: one award has a contract value, one has none.
	multi := `{"releases":[{"ocid":"ocds-h6vhtk-1","date":"2024-01-01","tag":["compiled"],
	  "buyer":{"name":"National Procurement Service (Welsh Government)"},
	  "awards":[
	    {"id":"A1","suppliers":[{"name":"Blake Morgan LLP"}]},
	    {"id":"A2","suppliers":[{"name":"No Value Co"}]}],
	  "contracts":[{"awardID":"A1","value":{"amount":60000000,"currency":"GBP"},"dateSigned":"2024-02-01"}],
	  "tender":{"value":{"amount":138000,"currency":"GBP"}}}]}`
	aws, err := parseOCDS([]byte(multi))
	if err != nil {
		t.Fatal(err)
	}
	by := map[string]award{}
	for _, a := range aws {
		by[a.id] = a
	}
	// A1 takes its contract value (and the contract's signing date); the
	// tender value is NOT applied because the release has more than one award.
	if by["A1"].amount != 60000000 || by["A1"].currency != "GBP" || by["A1"].date != "2024-02-01" {
		t.Errorf("A1 = %+v", by["A1"])
	}
	if by["A2"].amount != 0 {
		t.Errorf("A2 should have no amount (store skips it): %+v", by["A2"])
	}

	// A single-award release with no contract falls back to the tender value.
	single := `{"releases":[{"ocid":"ocds-h6vhtk-2","date":"2024-03-01","tag":["compiled"],
	  "buyer":{"name":"Police & Crime Commissioner for Dorset"},
	  "awards":[{"id":"B1","suppliers":[{"name":"Countrywide Grounds Maintenance Ltd"}]}],
	  "tender":{"value":{"amount":138000,"currency":"GBP"}}}]}`
	aws, err = parseOCDS([]byte(single))
	if err != nil || len(aws) != 1 {
		t.Fatalf("single-award parse: %v / %d", err, len(aws))
	}
	if aws[0].amount != 138000 || aws[0].currency != "GBP" {
		t.Errorf("tender fallback = %+v", aws[0])
	}
}

// TestScanBulkRwandaAndDR covers the two shapes validated for enabling:
// Rwanda carries the amount on award.value (RWF); the Dominican Republic
// leaves award.value empty and puts it on contracts[].value by awardID (DOP),
// with no buyer party.
func TestScanBulkRwandaAndDR(t *testing.T) {
	rw := `{"ocid":"ocds-ozzobm-1","date":"2024-06-01","buyer":{"name":"RWANDA FORENSIC INSTITUTE (RFI)"},` +
		`"awards":[{"id":"aw-rw","date":"2024-06-02","value":{"amount":24780000,"currency":"RWF"},` +
		`"suppliers":[{"name":"ROCK ASSOCIATES COMPANY LIMITED"}]}]}`
	do := `{"ocid":"ocds-6550wx-1","date":"2020-05-01",` +
		`"awards":[{"id":"DO1.AWD.883627","suppliers":[{"name":"Antonio Manuel Saviñon Santos"}]}],` +
		`"contracts":[{"awardID":"DO1.AWD.883627","value":{"amount":22892,"currency":"DOP"},"dateSigned":"2020-05-10"}]}`

	got := map[string]award{}
	match := func(s string) bool {
		return s == "ROCK ASSOCIATES COMPANY LIMITED" || s == "Antonio Manuel Saviñon Santos"
	}
	if _, err := scanBulk(strings.NewReader(rw+"\n"+do+"\n"), match, func(a award) { got[a.supplier] = a }); err != nil {
		t.Fatal(err)
	}

	rwa := got["ROCK ASSOCIATES COMPANY LIMITED"]
	if rwa.amount != 24780000 || rwa.currency != "RWF" || rwa.buyer != "RWANDA FORENSIC INSTITUTE (RFI)" {
		t.Errorf("rwanda = %+v", rwa)
	}
	doa := got["Antonio Manuel Saviñon Santos"]
	if doa.amount != 22892 || doa.currency != "DOP" || doa.date != "2020-05-10" {
		t.Errorf("dominican republic = %+v", doa)
	}
}

func TestReleasesFromLine(t *testing.T) {
	// A bare compiled release on the line.
	rels := releasesFromLine([]byte(`{"ocid":"ocds-1","awards":[{"id":"a","suppliers":[{"name":"Foo"}]}]}`))
	if len(rels) != 1 || rels[0].OCID != "ocds-1" {
		t.Errorf("compiled release line = %+v", rels)
	}
	// A release package on the line.
	rels = releasesFromLine([]byte(`{"releases":[{"ocid":"ocds-2","awards":[{"id":"a","suppliers":[{"name":"Bar"}]}]}]}`))
	if len(rels) != 1 || rels[0].OCID != "ocds-2" {
		t.Errorf("release package line = %+v", rels)
	}
}

func containsSupplier(u string) bool {
	for i := 0; i+10 <= len(u); i++ {
		if u[i:i+10] == "{supplier}" {
			return true
		}
	}
	return false
}
