// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package propublica

import "testing"

func TestParseSearch(t *testing.T) {
	body := []byte(`{"organizations":[
	  {"ein":142007220,"name":"Colgate University"},
	  {"ein":131234567,"name":"Colgate-Palmolive Foundation"}
	]}`)
	s, err := parseSearch(body)
	if err != nil || len(s.Organizations) != 2 {
		t.Fatalf("search = %+v err=%v", s, err)
	}
	if s.Organizations[0].EIN != 142007220 || s.Organizations[0].Name != "Colgate University" {
		t.Errorf("org0 = %+v", s.Organizations[0])
	}
}

func TestParseOrg(t *testing.T) {
	body := []byte(`{"organization":{"ein":142007220,"strein":"14-2007220","name":"Colgate University",
	  "address":"13 Oak Drive","city":"Hamilton","state":"NY","zipcode":"13346"},
	  "filings_with_data":[
	    {"tax_prd_yr":2022,"totrevenue":500000000,"totcntrbgfts":120000000},
	    {"tax_prd_yr":2021,"totrevenue":480000000,"totcntrbgfts":"95000000"}
	  ]}`)
	o, err := parseOrg(body)
	if err != nil {
		t.Fatal(err)
	}
	if o.Organization.StrEIN != "14-2007220" || o.Organization.City != "Hamilton" {
		t.Errorf("org = %+v", o.Organization)
	}
	if len(o.Filings) != 2 {
		t.Fatalf("filings = %d", len(o.Filings))
	}
	// Contributions figure, as a number and as a numeric string.
	if flexNum(o.Filings[0]["totcntrbgfts"]) != 120000000 {
		t.Errorf("filing0 contrib = %v", flexNum(o.Filings[0]["totcntrbgfts"]))
	}
	if flexNum(o.Filings[1]["totcntrbgfts"]) != 95000000 {
		t.Errorf("filing1 contrib = %v", flexNum(o.Filings[1]["totcntrbgfts"]))
	}
	if flexStr(o.Filings[0]["tax_prd_yr"]) != "2022" {
		t.Errorf("filing0 year = %q", flexStr(o.Filings[0]["tax_prd_yr"]))
	}
}

func TestNormalizeName(t *testing.T) {
	if normalizeName("Colgate University") != normalizeName("COLGATE  university.") {
		t.Error("normalization should ignore case and punctuation")
	}
	if normalizeName("A.B") != "a b" {
		t.Errorf("got %q", normalizeName("A.B"))
	}
}

func TestFlexStr(t *testing.T) {
	cases := map[string]string{
		`"hello"`: "hello",
		`1234`:    "1234",
		`12.5`:    "12.5",
		`null`:    "",
		``:        "",
	}
	for raw, want := range cases {
		if got := flexStr([]byte(raw)); got != want {
			t.Errorf("flexStr(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestFlexNum(t *testing.T) {
	cases := map[string]float64{
		`1234`:      1234,
		`"1234"`:    1234,
		`" 12.5 "`:  12.5,
		`"abc"`:     0,
		`null`:      0,
		`"1,000"`:   0, // commas are not stripped; not a valid float
	}
	for raw, want := range cases {
		if got := flexNum([]byte(raw)); got != want {
			t.Errorf("flexNum(%q) = %v, want %v", raw, got, want)
		}
	}
}
