// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
)

func TestResolversPublicResolvers(t *testing.T) {
	for _, server := range PublicResolvers {
		CustomResolvers = []string{server}

		a, err := ResolveDNS(testDomain, "A")
		if err != nil || len(a) == 0 {
			t.Errorf("%s failed to resolve the A record for %s", server, testDomain)
		}
	}
	CustomResolvers = []string{}
}
