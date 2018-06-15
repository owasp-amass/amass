// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"testing"
)

func TestArchiveTodayQuery(t *testing.T) {
	names := ArchiveTodayQuery(testDomain, testSubdomain)

	if len(names) <= 0 {
		t.Errorf("ArchiveTodayQuery did not find any subdomains")
	}
}
