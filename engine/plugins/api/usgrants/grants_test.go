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
