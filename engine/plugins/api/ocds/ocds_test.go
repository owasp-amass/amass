// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ocds

import "testing"

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
	// Seed publishers are disabled until a supplier-search endpoint is validated.
	for _, p := range pubs {
		if p.Enabled && !containsSupplier(p.QueryURL) {
			t.Errorf("publisher %s is enabled but its query_url cannot search by supplier", p.Key)
		}
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
