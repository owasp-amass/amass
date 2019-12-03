// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package requests

import (
	"testing"
)

func TestTrustedTag(t *testing.T) {
	tests := []struct {
		Value    string
		Expected bool
	}{
		{NONE, false},
		{ALT, false},
		{GUESS, false},
		{ARCHIVE, true},
		{API, false},
		{AXFR, true},
		{BRUTE, false},
		{CERT, true},
		{DNS, true},
		{EXTERNAL, false},
		{SCRAPE, false},
	}

	for _, test := range tests {
		if r := TrustedTag(test.Value); r != test.Expected {
			t.Errorf("%s returned %t instead of %t", test.Value, r, test.Expected)
		}
	}
}
