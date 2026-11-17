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
