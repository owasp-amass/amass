// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package edgar

import (
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

func TestParseTickers(t *testing.T) {
	body := []byte(`{
      "0": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc."},
      "1": {"cik_str": 789019, "ticker": "MSFT", "title": "Microsoft Corporation"},
      "2": {"cik_str": 0, "ticker": "", "title": ""},
      "3": {"cik_str": 1111, "ticker": "GIZA", "title": "Gizmo Corp"},
      "4": {"cik_str": 2222, "ticker": "GIZB", "title": "GIZMO INC"},
      "5": {"cik_str": 789019, "ticker": "MSFT2", "title": "MICROSOFT CORP"}
    }`)

	m, err := parseTickers(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := m[semantics.OrgNameKey("Apple Inc.")]; got != "0000320193" {
		t.Errorf("apple cik = %q", got)
	}
	if got := m[semantics.OrgNameKey("MICROSOFT CORPORATION")]; got != "0000789019" {
		t.Errorf("microsoft cik = %q", got)
	}
	// The empty row is skipped, two companies sharing the key "gizmo" are
	// left out, and one company listed twice keeps its key.
	if len(m) != 2 {
		t.Errorf("entries = %v, want apple and microsoft", m)
	}
}

func TestParseSubmissions(t *testing.T) {
	body := []byte(`{
      "cik": "320193", "name": "Apple Inc.", "phone": "(408) 996-1010",
      "addresses": {"business": {"street1": "ONE APPLE PARK WAY", "city": "CUPERTINO",
        "stateOrCountry": "CA", "zipCode": "95014"}},
      "filings": {"recent": {
        "accessionNumber": ["0001193125-23-000111", "0000320193-23-000106"],
        "form": ["D", "10-K"],
        "filingDate": ["2023-02-01", "2023-11-03"],
        "primaryDocument": ["primary_doc.xml", "aapl-20230930.htm"]
      }}
    }`)

	sub, err := parseSubmissions(body)
	if err != nil {
		t.Fatal(err)
	}
	if sub.Phone != "(408) 996-1010" {
		t.Errorf("phone = %q", sub.Phone)
	}
	if sub.Addresses.Business.City != "CUPERTINO" || sub.Addresses.Business.StateOrCountry != "CA" {
		t.Errorf("address = %+v", sub.Addresses.Business)
	}
	if len(sub.Filings.Recent.Form) != 2 || sub.Filings.Recent.Form[0] != "D" {
		t.Errorf("filings = %+v", sub.Filings.Recent)
	}

	if loc := businessAddress(&sub.Addresses.Business); loc == nil || loc.City != "cupertino" ||
		loc.Country != "US" || !strings.HasSuffix(loc.Address, ", CUPERTINO, CA 95014, US") {
		t.Errorf("location = %+v", loc)
	}
	if businessAddress(&address{}) != nil {
		t.Error("empty address should yield no location")
	}
}

func TestParseFormDAmount(t *testing.T) {
	xmlBody := []byte(`<?xml version="1.0"?>
      <edgarSubmission>
        <offeringData>
          <offeringSalesAmounts>
            <totalOfferingAmount>5000000</totalOfferingAmount>
            <totalAmountSold>3200000</totalAmountSold>
          </offeringSalesAmounts>
        </offeringData>
      </edgarSubmission>`)
	if got := parseFormDAmount(xmlBody); got != 3200000 {
		t.Errorf("amount = %v, want 3200000 (prefers amount sold)", got)
	}

	// Falls back to the offering amount when nothing was sold yet.
	fallback := []byte(`<edgarSubmission><offeringData><offeringSalesAmounts>
      <totalOfferingAmount>750000</totalOfferingAmount><totalAmountSold>0</totalAmountSold>
      </offeringSalesAmounts></offeringData></edgarSubmission>`)
	if got := parseFormDAmount(fallback); got != 750000 {
		t.Errorf("fallback amount = %v, want 750000", got)
	}

	// An indefinite/empty offering yields no amount.
	indefinite := []byte(`<edgarSubmission><offeringData><offeringSalesAmounts>
      <totalOfferingAmount>Indefinite</totalOfferingAmount><totalAmountSold>0</totalAmountSold>
      </offeringSalesAmounts></offeringData></edgarSubmission>`)
	if got := parseFormDAmount(indefinite); got != 0 {
		t.Errorf("indefinite amount = %v, want 0", got)
	}
}

func TestBusinessAddress(t *testing.T) {
	// A US address comes out in standard form with its country.
	loc := businessAddress(&address{Street1: "1 Infinite Loop", Street2: "Suite 100",
		City: "Cupertino", StateOrCountry: "CA", ZipCode: "95014"})
	if loc == nil || loc.City != "cupertino" || loc.Province != "CA" || loc.PostalCode != "95014" ||
		loc.Country != "US" || !strings.HasSuffix(loc.Address, ", CUPERTINO, CA 95014, US") {
		t.Errorf("full address = %+v", loc)
	}

	// A city without a street still locates the filer.
	if loc := businessAddress(&address{City: "Reno", StateOrCountry: "NV"}); loc == nil ||
		loc.City != "reno" || loc.Address != "RENO, NV, US" {
		t.Errorf("city-only = %+v", loc)
	}

	// No city, or a country EDGAR names by its own code: nothing to store.
	if loc := businessAddress(&address{StateOrCountry: "NY", ZipCode: "10001"}); loc != nil {
		t.Errorf("no city should be nil, got %+v", loc)
	}
	if loc := businessAddress(&address{Street1: "1 High St", City: "London", StateOrCountry: "X0"}); loc != nil {
		t.Errorf("a foreign EDGAR code should be nil, got %+v", loc)
	}
}
