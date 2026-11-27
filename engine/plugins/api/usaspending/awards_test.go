// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usaspending

import "testing"

const sampleAwardsPage = `{
  "results": [
    {"Award ID": "FA860123C0001", "Recipient Name": "UTICA UNIVERSITY", "Award Amount": 2500000.0,
     "Awarding Agency": "Department of Defense", "Start Date": "2023-04-01",
     "generated_internal_id": "CONT_AWD_FA860123C0001"},
    {"Award ID": "R01GM000001", "Recipient Name": "Utica University", "Award Amount": 480000.5,
     "Awarding Agency": "Department of Health and Human Services", "Start Date": "2022-09-15",
     "generated_internal_id": ""},
    {"Award ID": "X9", "Recipient Name": "Utica Products Company", "Award Amount": 9999.0,
     "Awarding Agency": "GSA", "Start Date": "2021-01-01", "generated_internal_id": "CONT_AWD_X9"}
  ],
  "page_metadata": {"hasNext": true}
}`

func TestParseAwards(t *testing.T) {
	rows, hasNext, err := parseAwards([]byte(sampleAwardsPage))
	if err != nil {
		t.Fatal(err)
	}
	if !hasNext {
		t.Error("hasNext should be true")
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %d, want 3", len(rows))
	}
	if rows[0].Amount != 2500000.0 || rows[0].Agency != "Department of Defense" {
		t.Errorf("row0 = %+v", rows[0])
	}
	if rows[0].transferID() != "CONT_AWD_FA860123C0001" {
		t.Errorf("row0 id = %q", rows[0].transferID())
	}
	// No generated id falls back to the award id.
	if rows[1].transferID() != "usaspending:R01GM000001" {
		t.Errorf("row1 id = %q", rows[1].transferID())
	}
}

func TestParseAwardsEmpty(t *testing.T) {
	rows, hasNext, err := parseAwards([]byte(`{"results": [], "page_metadata": {"hasNext": false}}`))
	if err != nil || hasNext || len(rows) != 0 {
		t.Fatalf("rows=%v hasNext=%v err=%v", rows, hasNext, err)
	}
}
