// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"slices"
	"testing"
)

func TestSOAMailbox(t *testing.T) {
	for rname, want := range map[string]string{
		"hostmaster.example.com.":      "hostmaster@example.com",
		"John\\.Doe.example.co.uk.":    "john.doe@example.co.uk",
		"awsdns-hostmaster.amazon.com": "awsdns-hostmaster@amazon.com",
		"hostmaster.":                  "",
		"example.com":                  "",
		"":                             "",
	} {
		if got := soaMailbox(rname); got != want {
			t.Errorf("soaMailbox(%q) = %q, want %q", rname, got, want)
		}
	}
}

func TestSPFAuthorizedRanges(t *testing.T) {
	txt := "v=spf1 ip4:192.0.2.0/24 +ip4:198.51.100.7 ip6:2001:db8:1234::/48 -ip4:203.0.113.0/24 " +
		"ip4:10.0.0.0/8 ip4:8.0.0.0/8 ip4:not-an-ip include:_spf.example.net ~all"
	var got []string
	for _, p := range spfAuthorizedRanges(txt) {
		got = append(got, p.String())
	}
	// the excluded, private, overly broad and unreadable ranges are dropped
	want := []string{"192.0.2.0/24", "198.51.100.7/32", "2001:db8:1234::/48"}
	if !slices.Equal(got, want) {
		t.Errorf("ranges %v, want %v", got, want)
	}
	if spfAuthorizedRanges("v=DMARC1; p=none") != nil {
		t.Error("a non-SPF record gave ranges")
	}
}
