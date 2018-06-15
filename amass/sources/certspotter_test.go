// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"testing"
)

func TestCertSpotterQuery(t *testing.T) {
	names := CertSpotterQuery(testDomain, testDomain)

	if len(names) <= 0 {
		t.Errorf("CertSpotterQuery did not find any subdomains")
	}
}
