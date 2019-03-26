// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"flag"
	"os"
	"testing"
	"time"
)

var (
	networkTest  = flag.Bool("network", false, "Run tests that require connectivity (take more time)")
	domainTest   = "owasp.org"
	expectedTest = 1
	doneTest     = time.After(time.Second * 30)
)

// TestMain will parse the test flags and setup for integration tests.
func TestMain(m *testing.M) {
	flag.Parse()

	result := m.Run()

	os.Exit(result)
}

func TestCleanName(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		expected string
	}{
		{"Test 1: Domain", " .owasp.org", "owasp.org"},
		{"Test 2: Subdomain", ".sub.owasp.org", "sub.owasp.org"},
	}

	for _, tt := range tests {
		result := cleanName(tt.domain)
		if result != tt.expected {
			t.Errorf("Failed %s: got %s expected %s", tt.name, result, tt.expected)
		}
	}
}
