// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"testing"
)

func TestFindSubdomainsQuery(t *testing.T) {
	names := FindSubdomainsQuery(testDomain, testDomain)

	if len(names) <= 0 {
		t.Errorf("FindSubdomainsQuery did not find any subdomains")
	}
}
