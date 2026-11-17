// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package osm

import (
	"strings"
	"testing"
)

const sampleOverpass = `{
  "elements": [
    {"type": "node", "id": 123, "tags": {"name": "Colgate University", "phone": "+1-315-228-1000"}},
    {"type": "way", "id": 456, "tags": {"name": "COLGATE UNIVERSITY", "contact:phone": "+1 315 228 7000; +1 315 228 7001"}},
    {"type": "node", "id": 789, "tags": {"name": "Colgate Inn", "phone": "+1-315-228-0000"}}
  ]
}`

func TestParseOverpass(t *testing.T) {
	els, err := parseOverpass([]byte(sampleOverpass))
	if err != nil {
		t.Fatal(err)
	}
	if len(els) != 3 {
		t.Fatalf("elements = %d, want 3", len(els))
	}
	if els[0].url() != "https://www.openstreetmap.org/node/123" {
		t.Errorf("url = %q", els[0].url())
	}
	// Semicolon-separated numbers are split.
	nums := els[1].phoneNumbers()
	if len(nums) != 2 || nums[0] != "+1 315 228 7000" || nums[1] != "+1 315 228 7001" {
		t.Errorf("phoneNumbers = %+v", nums)
	}
}

func TestSameName(t *testing.T) {
	cases := []struct {
		org, feature string
		want         bool
	}{
		{"Colgate University", "Colgate University", true},
		{"Colgate University", "COLGATE UNIVERSITY", true},
		{"Colgate University", "Colgate  University.", true},
		{"Colgate University", "Colgate Inn", false}, // a same-town, different place
		{"Colgate University", "", false},
	}
	for _, c := range cases {
		if got := sameName(c.org, c.feature); got != c.want {
			t.Errorf("sameName(%q,%q) = %v, want %v", c.org, c.feature, got, c.want)
		}
	}
}

func TestBuildQueryEscapes(t *testing.T) {
	q := buildQuery("A.B (C)")
	// Regex metacharacters in the name are escaped so they match literally.
	for _, want := range []string{`A\.B \(C\)`, `["phone"]`, `["contact:phone"]`, "out tags center"} {
		if !strings.Contains(q, want) {
			t.Errorf("query missing %q:\n%s", want, q)
		}
	}
}
