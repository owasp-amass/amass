// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "testing"

func TestIsDefaultFingerprint(t *testing.T) {
	cases := []struct {
		idType, value string
		want          bool
	}{
		{"http_title", "Welcome to nginx!", true},
		{"http_title", "  WELCOME TO NGINX!  ", true}, // matched after case-folding and trimming
		{"http_title", "404 Not Found", true},
		{"http_title", "OWASP Foundation Alumni Portal", false}, // a distinctive title is kept
		{"favicon_mmh3", "123456", false},                       // no favicon defaults confirmed yet
		{"analytics_id", "GTM-K9X2ZQ", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := IsDefaultFingerprint(c.idType, c.value); got != c.want {
			t.Errorf("IsDefaultFingerprint(%q, %q) = %v, want %v", c.idType, c.value, got, c.want)
		}
	}
}

// TestFingerprintDefaultsLoad fails if the catalog is malformed or an entry
// lacks a citation (the loader panics), and confirms it carries default titles.
func TestFingerprintDefaultsLoad(t *testing.T) {
	if m := loadFingerprintDefaults(); len(m["http_title"]) == 0 {
		t.Error("expected default page titles in fingerprint_defaults.json")
	}
}
