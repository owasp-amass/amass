// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dnssrv

const TestDomain string = "owasp.org"

/*
func TestResolversPublicResolvers(t *testing.T) {
	for _, server := range PublicResolvers {
		CustomResolvers = []string{server}

		a, err := Resolve(TestDomain, "A")
		if err != nil || len(a) == 0 {
			t.Errorf("%s failed to resolve the A record for %s", server, TestDomain)
		}
	}
	CustomResolvers = []string{}
}
*/
