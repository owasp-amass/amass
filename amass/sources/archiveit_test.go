// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"testing"
)

const (
	testDomain    string = "utica.edu"
	testSubdomain string = "www.utica.edu"
)

func TestArchiveItQuery(t *testing.T) {
	names := ArchiveItQuery(testDomain, testSubdomain)

	if len(names) <= 0 {
		t.Errorf("ArchiveItQuery did not find any subdomains")
	}
}
