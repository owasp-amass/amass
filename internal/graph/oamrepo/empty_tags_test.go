// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"errors"
	"testing"
)

func TestEmptyTagLookupDoesNotSwallowOtherErrors(t *testing.T) {
	cases := []struct {
		message string
		want    bool
	}{
		{"no tags found for edge", true},
		{"no tags found for entity", true},
		{"no edge tags found", true},
		{"zero tags found", true},
		{"database is locked", false},
		{"connection refused", false},
		{"permission denied", false},
		{"invalid edge ID", false},
		{"no tags found for edges", false},
	}
	for _, tc := range cases {
		got := emptyTagLookup(errors.New(tc.message))
		if got != tc.want {
			t.Errorf("%q: got empty=%t, want %t", tc.message, got, tc.want)
		}
	}
}
