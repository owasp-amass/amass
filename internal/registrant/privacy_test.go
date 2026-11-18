// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registrant

import "testing"

func TestDetectRegistrantPlaceholder(t *testing.T) {
	cases := []struct {
		value string
		proxy bool
	}{
		{"Domains By Proxy, LLC", true},
		{"WhoisGuard, Inc.", true},
		{"Contact Privacy Inc. Customer 0123456789", true},
		{"REDACTED FOR PRIVACY", true},
		{"Perfect Privacy, LLC", true},
		{"Identity Protected", true},
		{"n/a", false}, // score 4, below the placeholder threshold on its own
		{"Ithaca College", false},
		{"State University of New York", false},
		{"", false},
	}
	for _, c := range cases {
		if got := IsPrivacyProxyName(c.value); got != c.proxy {
			d := DetectRegistrantPlaceholder(c.value)
			t.Errorf("IsPrivacyProxyName(%q) = %v, want %v (score %d, matches %+v)",
				c.value, got, c.proxy, d.Score, d.Matches)
		}
	}
}
