// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

func TestParseNSF(t *testing.T) {
	body := []byte(`{"response":{"award":[
	  {"id":"2012345","awardeeName":"OWASP Foundation","fundsObligatedAmt":"450000","agency":"NSF","date":"03/01/2023"},
	  {"id":"2098765","awardeeName":"OWASP Foundation","fundsObligatedAmt":"","agency":"NSF","date":"09/15/2022"}
	]}}`)
	g, err := parseNSF(body)
	if err != nil || len(g) != 2 {
		t.Fatalf("grants=%v err=%v", g, err)
	}
	if g[0].id != "nsf:2012345" || g[0].amount != 450000 || g[0].recipient != "OWASP Foundation" {
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
	   "organization":{"org_name":"OWASP FOUNDATION"},
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
	if g[0].agency != "National Institute of General Medical Sciences" || g[0].recipient != "OWASP FOUNDATION" {
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

func TestParseSBIRAwards(t *testing.T) {
	body := "\ufeffCompany,Award Title,Agency,Contract,Proposal Award Date,Award Year,Award Amount\n" +
		"Acme Research Inc,Widget,DOD,FA8750-23-C-0001,2023-02-01,2023,1500000\n" +
		"ACME RESEARCH INC.,Gadget Study,NASA,,,2022,\"$750,000.50\"\n" +
		"Acme Research Inc,No Money,DOD,X-1,,2021,0\n" +
		",Orphan,DOD,X-2,,2021,100\n" +
		"Acme Research Inc,,DOD,,,2020,100\n" +
		"Other Labs LLC,Thing,NSF,NSF-9,,2024,5000\n"

	byKey, err := parseSBIRAwards(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	g := byKey[semantics.OrgNameKey("Acme Research Inc")]
	if len(g) != 2 {
		t.Fatalf("Acme's awards = %+v; want the two with an amount and an identity", g)
	}
	if g[0].id != "sbir:FA8750-23-C-0001" || g[0].amount != 1500000 || g[0].date != "2023-02-01" || g[0].agency != "DOD" {
		t.Errorf("g0 = %+v", g[0])
	}
	// No contract: the ID comes from the title and year, and the year is the date.
	if g[1].id != "sbir:Gadget_Study:2022" || g[1].amount != 750000.50 || g[1].date != "2022" {
		t.Errorf("g1 = %+v", g[1])
	}
	if len(byKey[semantics.OrgNameKey("Other Labs LLC")]) != 1 {
		t.Errorf("Other Labs' award is missing: %v", byKey)
	}

	if _, err := parseSBIRAwards(strings.NewReader("Name,Amount\nAcme,5\n")); err == nil {
		t.Error("a file without the Company and Award Amount columns was accepted")
	}
}
