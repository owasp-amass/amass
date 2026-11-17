// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"encoding/json"
	"testing"
)

func TestParseNSF(t *testing.T) {
	body := []byte(`{"response":{"award":[
	  {"id":"2012345","awardeeName":"Colgate University","fundsObligatedAmt":"450000","agency":"NSF","date":"03/01/2023"},
	  {"id":"2098765","awardeeName":"Colgate University","fundsObligatedAmt":"","agency":"NSF","date":"09/15/2022"}
	]}}`)
	g, err := parseNSF(body)
	if err != nil || len(g) != 2 {
		t.Fatalf("grants=%v err=%v", g, err)
	}
	if g[0].id != "nsf:2012345" || g[0].amount != 450000 || g[0].recipient != "Colgate University" {
		t.Errorf("g0 = %+v", g[0])
	}
	if g[0].agency != "National Science Foundation" {
		t.Errorf("agency mapping = %q", g[0].agency)
	}
	if g[1].amount != 0 { // empty amount tolerated
		t.Errorf("g1 amount = %v", g[1].amount)
	}
}

func TestParseNIH(t *testing.T) {
	body := []byte(`{"results":[
	  {"project_num":"5R01GM000001-02","award_amount":325000,
	   "organization":{"org_name":"COLGATE UNIVERSITY"},
	   "agency_ic_admin":{"name":"National Institute of General Medical Sciences"},
	   "fiscal_year":2023,"project_start_date":"2023-04-01T00:00:00Z"}
	],"meta":{"total":1}}`)
	g, err := parseNIH(body)
	if err != nil || len(g) != 1 {
		t.Fatalf("grants=%v err=%v", g, err)
	}
	if g[0].id != "nih:5R01GM000001-02" || g[0].amount != 325000 {
		t.Errorf("g0 = %+v", g[0])
	}
	if g[0].agency != "National Institute of General Medical Sciences" || g[0].recipient != "COLGATE UNIVERSITY" {
		t.Errorf("agency/recipient = %+v", g[0])
	}
}

// TestParseNIHAmountFallbacks checks every project gets a dollar amount with
// the real RePORTER field shapes, exercising each fallback: award_amount,
// then direct_cost_amt+indirect_cost_amt, then the agency_ic_fundings array.
// The first three records' values are from a live SUNY Polytechnic Institute
// response; the last two force the fallbacks.
func TestParseNIHAmountFallbacks(t *testing.T) {
	body := []byte(`{"meta":{"total":5},"results":[
	 {"project_num":"3R15CA274603-01S1","award_amount":296920,"direct_cost_amt":200000,"indirect_cost_amt":96920,
	  "agency_ic_fundings":[{"total_cost":296920.0}],"organization":{"org_name":"SUNY POLYTECHNIC INSTITUTE"},
	  "agency_ic_admin":{"name":"National Cancer Institute"},"fiscal_year":2023,"project_start_date":"2023-08-01T00:00:00"},
	 {"project_num":"1R15CA274603-01","award_amount":459347,"direct_cost_amt":333739,"indirect_cost_amt":125608,
	  "agency_ic_fundings":[{"total_cost":459347.0}],"organization":{"org_name":"SUNY POLYTECHNIC INSTITUTE"},
	  "agency_ic_admin":{"name":"National Cancer Institute"},"fiscal_year":2022,"project_start_date":"2022-08-24T00:00:00"},
	 {"project_num":"3R01GM125870-04S1","award_amount":319793,"direct_cost_amt":208334,"indirect_cost_amt":111459,
	  "agency_ic_fundings":[{"total_cost":319793.0}],"organization":{"org_name":"SUNY POLYTECHNIC INSTITUTE"},
	  "agency_ic_admin":{"name":"National Institute of General Medical Sciences"},"fiscal_year":2018,"project_start_date":"2018-01-01T00:00:00"},
	 {"project_num":"FALLBACK-DIRECT-INDIRECT","award_amount":0,"direct_cost_amt":333739,"indirect_cost_amt":125608,
	  "organization":{"org_name":"SUNY POLYTECHNIC INSTITUTE"},
	  "agency_ic_admin":{"name":"National Cancer Institute"},"fiscal_year":2022,"project_start_date":"2022-08-24T00:00:00"},
	 {"project_num":"FALLBACK-IC-SUM","award_amount":0,"direct_cost_amt":0,"indirect_cost_amt":0,
	  "agency_ic_fundings":[{"total_cost":200000.0},{"total_cost":119793.0}],"organization":{"org_name":"SUNY POLYTECHNIC INSTITUTE"},
	  "agency_ic_admin":{"name":"National Institute of General Medical Sciences"},"fiscal_year":2018,"project_start_date":"2018-01-01T00:00:00"}
	]}`)
	g, err := parseNIH(body)
	if err != nil || len(g) != 5 {
		t.Fatalf("grants=%v err=%v", g, err)
	}

	want := map[string]float64{
		"nih:3R15CA274603-01S1":        296920,
		"nih:1R15CA274603-01":          459347,
		"nih:3R01GM125870-04S1":        319793,
		"nih:FALLBACK-DIRECT-INDIRECT": 459347, // award_amount 0 -> direct+indirect
		"nih:FALLBACK-IC-SUM":          319793, // all else 0 -> sum agency_ic_fundings
	}
	got := map[string]float64{}
	for _, x := range g {
		got[x.id] = x.amount
	}
	for id, amt := range want {
		if got[id] != amt {
			t.Errorf("%s amount = %v, want %v", id, got[id], amt)
		}
	}
}

func TestParseSBIR(t *testing.T) {
	// Amount as a number in one, a string in the other — both must parse.
	body := []byte(`[
	  {"firm":"Acme Research Inc","agency":"DOD","contract":"FA8750-23-C-0001","award_title":"Widget","award_year":2023,"award_amount":1500000},
	  {"firm":"Acme Research Inc","agency":"NASA","contract":"","award_title":"Gadget Study","award_year":"2022","award_amount":"750000"}
	]`)
	g, err := parseSBIR(body)
	if err != nil || len(g) != 2 {
		t.Fatalf("grants=%v err=%v", g, err)
	}
	if g[0].id != "sbir:FA8750-23-C-0001" || g[0].amount != 1500000 {
		t.Errorf("g0 = %+v", g[0])
	}
	// No contract → id composed from title and year; amount from string.
	if g[1].id != "sbir:Gadget_Study:2022" || g[1].amount != 750000 || g[1].date != "2022" {
		t.Errorf("g1 = %+v", g[1])
	}
}

func TestFlexNumStr(t *testing.T) {
	if flexNum(json.RawMessage(`1200`)) != 1200 || flexNum(json.RawMessage(`"3400"`)) != 3400 {
		t.Error("flexNum should parse number and numeric string")
	}
	if flexStr(json.RawMessage(`2024`)) != "2024" || flexStr(json.RawMessage(`"x"`)) != "x" {
		t.Error("flexStr should render number and string")
	}
}

func TestRecipientMatches(t *testing.T) {
	if !recipientMatches("Colgate University", "COLGATE UNIVERSITY") {
		t.Error("case-insensitive match expected")
	}
	if recipientMatches("Colgate University", "Colgate Research LLC") {
		t.Error("different entity should not match")
	}
}
