// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package edgar

import "testing"

func TestParseTickers(t *testing.T) {
	body := []byte(`{
      "0": {"cik_str": 320193, "ticker": "AAPL", "title": "Apple Inc."},
      "1": {"cik_str": 789019, "ticker": "MSFT", "title": "Microsoft Corporation"},
      "2": {"cik_str": 0, "ticker": "", "title": ""}
    }`)

	m, err := parseTickers(body)
	if err != nil {
		t.Fatal(err)
	}
	if got := m[normalizeName("Apple Inc.")]; got != "0000320193" {
		t.Errorf("apple cik = %q", got)
	}
	if got := m[normalizeName("MICROSOFT CORPORATION")]; got != "0000789019" {
		t.Errorf("microsoft cik = %q", got)
	}
	// The empty row is skipped.
	if len(m) != 2 {
		t.Errorf("entries = %d, want 2", len(m))
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

	if loc := businessLocation(&sub.Addresses.Business); loc == nil || loc.City != "CUPERTINO" ||
		loc.Address != "ONE APPLE PARK WAY" {
		t.Errorf("location = %+v", loc)
	}
	if businessLocation(&address{}) != nil {
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
