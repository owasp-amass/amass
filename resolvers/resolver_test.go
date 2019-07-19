// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package resolvers

import (
	"flag"
	"os"
	"testing"
)

const TestDomain string = "owasp-amass.com"

var (
	networkTest = flag.Bool("network", false, "Run tests that require connectivity (take more time)")
)

// TestMain will parse the test flags and setup for integration tests.
func TestMain(m *testing.M) {
	flag.Parse()

	result := m.Run()

	os.Exit(result)
}

func TestZoneTransfer(t *testing.T) {
	if *networkTest == false {
		return
	}

	tests := []struct {
		expected string
	}{
		{"amass-transfer-test.axfr.owasp-amass.com"},
		{"exchange2003.axfr.owasp-amass.com"},
		{"i-should-get-some-sleep.axfr.owasp-amass.com"},
		{"its-almost-2am-here.axfr.owasp-amass.com"},
		{"stormstroopers.axfr.owasp-amass.com"},
		{"top-secret-sub-domain.axfr.owasp-amass.com"},
		{"vpn.axfr.owasp-amass.com"},
		{"youll-never-find-this.axfr.owasp-amass.com"},
	}
	a, err := ZoneTransfer(TestDomain, TestDomain, "ns1.owasp-amass.com")
	if err != nil {
		t.Errorf("Error in creating ZoneTransfer: %v", err)
	}
	var s []string
	var check int
	for _, out := range a {
		for _, test := range tests {
			if test.expected == out.Name {
				s = append(s, out.Name)
				check++
			}
		}
		if check < len(tests) {
			t.Errorf("Did not find all expected sub domains. \n Found %v", s)
		}
	}
}
