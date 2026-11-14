// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"slices"
	"testing"
)

func TestNameTokensAreDistinctive(t *testing.T) {
	def, _ := firstSignal(matchNameToken)
	if got := nameTokens("Colgate University", def.Params); !slices.Equal(got, []string{"colgate"}) {
		t.Errorf("tokens = %v", got)
	}
	if got := nameTokens("The OWASP Foundation, Inc.", def.Params); !slices.Equal(got, []string{"owasp"}) {
		t.Errorf("tokens = %v (foundation is generic)", got)
	}
	if got := nameTokens("Acme Holdings Group", def.Params); len(got) != 0 {
		t.Errorf("tokens = %v (acme is too short, the rest are generic)", got)
	}
}

func TestRedirectHost(t *testing.T) {
	cases := map[[2]string]string{
		{"location", "https://www.colgate.edu/x"}:     "www.colgate.edu",
		{"location", "/relative/path"}:                "",
		{"refresh", "0; url=https://colgate.edu/"}:    "colgate.edu",
		{"refresh", "5;URL='http://www.colgate.edu'"}: "www.colgate.edu",
		{"refresh", "10"}:                             "",
	}
	for in, want := range cases {
		if got := redirectHost(in[0], in[1]); got != want {
			t.Errorf("redirectHost(%q, %q) = %q, want %q", in[0], in[1], got, want)
		}
	}
}
