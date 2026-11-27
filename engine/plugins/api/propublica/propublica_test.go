// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package propublica

import (
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
)

func TestParseSearch(t *testing.T) {
	body := []byte(`{"organizations":[
	  {"ein":990000001,"name":"Utica University"},
	  {"ein":131234567,"name":"Utica Products Foundation"}
	]}`)
	s, err := parseSearch(body)
	if err != nil || len(s.Organizations) != 2 {
		t.Fatalf("search = %+v err=%v", s, err)
	}
	if s.Organizations[0].EIN != 990000001 || s.Organizations[0].Name != "Utica University" {
		t.Errorf("org0 = %+v", s.Organizations[0])
	}
}

func TestParseOrg(t *testing.T) {
	body := []byte(`{"organization":{"ein":990000001,"strein":"99-0000001","name":"Utica University",
	  "address":"100 Main Street","city":"Utica","state":"NY","zipcode":"13502"},
	  "filings_with_data":[
	    {"tax_prd_yr":2022,"totrevenue":500000000,"totcntrbgfts":120000000},
	    {"tax_prd_yr":2021,"totrevenue":480000000,"totcntrbgfts":"95000000"}
	  ]}`)
	o, err := parseOrg(body)
	if err != nil {
		t.Fatal(err)
	}
	if o.Organization.StrEIN != "99-0000001" || o.Organization.City != "Utica" {
		t.Errorf("org = %+v", o.Organization)
	}
	if len(o.Filings) != 2 {
		t.Fatalf("filings = %d", len(o.Filings))
	}
	// Contributions figure, as a number and as a numeric string.
	if support.JSONNumber(o.Filings[0]["totcntrbgfts"]) != 120000000 {
		t.Errorf("filing0 contrib = %v", support.JSONNumber(o.Filings[0]["totcntrbgfts"]))
	}
	if support.JSONNumber(o.Filings[1]["totcntrbgfts"]) != 95000000 {
		t.Errorf("filing1 contrib = %v", support.JSONNumber(o.Filings[1]["totcntrbgfts"]))
	}
	if support.JSONString(o.Filings[0]["tax_prd_yr"]) != "2022" {
		t.Errorf("filing0 year = %q", support.JSONString(o.Filings[0]["tax_prd_yr"]))
	}
}
