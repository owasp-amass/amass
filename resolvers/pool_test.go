// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"testing"

	"github.com/OWASP/Amass/requests"
)

func TestResolverPoolWildcardDetection(t *testing.T) {
	pool := SetupResolverPool([]string{"8.8.8.8"}, false, false)
	if pool == nil {
		return
	}

	req := &requests.DNSRequest{
		Name:   "random.wildcard.owasp-amass.com",
		Domain: "wildcard.owasp-amass.com",
	}

	if !pool.MatchesWildcard(req) {
		t.Errorf("DNS wildcard detection failed to identify the %s wildcard", req.Domain)
	}

	req = &requests.DNSRequest{
		Name:   "www.utica.edu",
		Domain: "utica.edu",
	}

	if pool.MatchesWildcard(req) {
		t.Errorf("DNS wildcard detection reported a false positive for %s", req.Domain)
	}
}
