// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ted

import (
	"encoding/json"
	"testing"
)

func TestFlexStrings(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{`"Acme Oy"`, []string{"Acme Oy"}},                              // scalar
		{`["Acme Oy","Beta AB"]`, []string{"Acme Oy", "Beta AB"}},       // list
		{`{"eng":"Acme","fin":"Acme Oy"}`, []string{"Acme", "Acme Oy"}}, // multilingual map
		{`1234`, []string{"1234"}},                                      // number
		{`null`, nil},
	}
	for _, c := range cases {
		got := flexStrings(json.RawMessage(c.in))
		if len(got) != len(c.want) {
			t.Errorf("flexStrings(%s) = %v, want %v", c.in, got, c.want)
			continue
		}
		set := map[string]bool{}
		for _, g := range got {
			set[g] = true
		}
		for _, w := range c.want {
			if !set[w] {
				t.Errorf("flexStrings(%s) = %v, missing %q", c.in, got, w)
			}
		}
	}
}

func TestFlexFloat(t *testing.T) {
	if got := flexFloat(json.RawMessage(`5000000`)); got != 5000000 {
		t.Errorf("number = %v", got)
	}
	if got := flexFloat(json.RawMessage(`"2500000.50"`)); got != 2500000.50 {
		t.Errorf("string = %v", got)
	}
	if got := flexFloat(json.RawMessage(`["0","750000"]`)); got != 750000 {
		t.Errorf("list = %v", got)
	}
	if got := flexFloat(json.RawMessage(`"n/a"`)); got != 0 {
		t.Errorf("non-numeric = %v", got)
	}
}

func TestParseNoticesBothWrappers(t *testing.T) {
	// The "notices" wrapper.
	a, err := parseNotices([]byte(`{"notices":[{"winner-name":"Acme Oy"}],"totalNoticeCount":1}`))
	if err != nil || len(a) != 1 {
		t.Fatalf("notices wrapper: %v %v", a, err)
	}
	// The "results" wrapper.
	b, err := parseNotices([]byte(`{"results":[{"winner-name":"Beta AB"},{"winner-name":"Gamma"}]}`))
	if err != nil || len(b) != 2 {
		t.Fatalf("results wrapper: %v %v", b, err)
	}
}

// realNotices mirrors the actual TED response shapes: the notices wrapper, a
// scalar total-value, a list total-value-cur, and buyer-name/winner-name as
// language-keyed maps of lists. The award notice carries a winner but no
// total-value.
const realNotices = `{"notices":[
  {"publication-number":"797069-2026","buyer-name":{"deu":["Stadt Husum"]},
   "total-value-cur":["EUR"],"publication-date":"2026-11-17+01:00","total-value":900000},
  {"publication-number":"700000-2026","buyer-name":{"deu":["Stadt Kiel"]},
   "publication-date":"2026-11-10+01:00","winner-name":{"deu":["Planungsgruppe M+M AG"]}}
],"totalNoticeCount":2}`

func TestExtractRealShapes(t *testing.T) {
	notices, err := parseNotices([]byte(realNotices))
	if err != nil || len(notices) != 2 {
		t.Fatalf("notices=%d err=%v", len(notices), err)
	}

	// The first notice has a value but no winner — not an award to anyone.
	if winnerMatches("Stadt Husum", flexStrings(notices[0]["winner-name"])) {
		t.Error("notice 0 has no winner and should not match")
	}
	if flexFloat(notices[0]["total-value"]) != 900000 {
		t.Errorf("notice 0 value = %v", flexFloat(notices[0]["total-value"]))
	}
	if first(flexStrings(notices[0]["total-value-cur"])) != "EUR" {
		t.Errorf("notice 0 currency = %q", first(flexStrings(notices[0]["total-value-cur"])))
	}

	// The second notice names a winner (multilingual map) but carries no value.
	if !winnerMatches("Planungsgruppe M+M AG", flexStrings(notices[1]["winner-name"])) {
		t.Error("notice 1 winner should match from the language-keyed map")
	}
	if first(flexStrings(notices[1]["buyer-name"])) != "Stadt Kiel" {
		t.Errorf("notice 1 buyer = %q", first(flexStrings(notices[1]["buyer-name"])))
	}
}

func TestWinnerMatches(t *testing.T) {
	if !winnerMatches("Acme Oy", []string{"ACME OY"}) {
		t.Error("should match case-insensitively")
	}
	if !winnerMatches("Acme Oy", []string{"Other Co", "Acme  Oy."}) {
		t.Error("should match one of several winners, ignoring punctuation")
	}
	if winnerMatches("Acme Oy", []string{"Acme Services Oy"}) {
		t.Error("should not match a different organization")
	}
	if winnerMatches("Acme Oy", nil) {
		t.Error("no winners, no match")
	}
}
