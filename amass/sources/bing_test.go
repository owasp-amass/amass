// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"testing"
)

func TestBingQuery(t *testing.T) {
	names := BingQuery(testDomain, testDomain)

	if len(names) <= 0 {
		t.Errorf("BingQuery did not find any subdomains")
	}
}
