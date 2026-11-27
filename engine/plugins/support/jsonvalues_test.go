// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"encoding/json"
	"slices"
	"testing"
)

func TestJSONStrings(t *testing.T) {
	for _, c := range []struct {
		in   string
		want []string
	}{
		{`"Acme Oy"`, []string{"Acme Oy"}},
		{`["Acme Oy","Beta AB"]`, []string{"Acme Oy", "Beta AB"}},
		{`{"eng":"Acme","fin":["Acme Oy"]}`, []string{"Acme", "Acme Oy"}},
		{`1234`, []string{"1234"}},
		{`12.5`, []string{"12.5"}},
		{`""`, nil},
		{`null`, nil},
		{``, nil},
	} {
		got := JSONStrings(json.RawMessage(c.in))
		slices.Sort(got)
		if !slices.Equal(got, c.want) {
			t.Errorf("JSONStrings(%s) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestJSONString(t *testing.T) {
	for in, want := range map[string]string{
		`"hello"`:          "hello",
		`2024`:             "2024",
		`["", " ", "x"]`:   "x",
		`{"deu":"Kiel"}`:   "Kiel",
		`null`:             "",
		``:                 "",
		`{"a":{"b":null}}`: "",
	} {
		if got := JSONString(json.RawMessage(in)); got != want {
			t.Errorf("JSONString(%s) = %q, want %q", in, got, want)
		}
	}
}

func TestJSONNumber(t *testing.T) {
	for in, want := range map[string]float64{
		`5000000`:        5000000,
		`"2500000.50"`:   2500000.50,
		`" 12.5 "`:       12.5,
		`["0","750000"]`: 750000,
		`"n/a"`:          0,
		`"1,000"`:        0, // commas are not stripped
		`-5`:             0,
		`null`:           0,
	} {
		if got := JSONNumber(json.RawMessage(in)); got != want {
			t.Errorf("JSONNumber(%s) = %v, want %v", in, got, want)
		}
	}
}
