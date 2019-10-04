// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dns

import (
	"testing"
)

func TestSubdomainRegex(t *testing.T) {
	tests := []struct {
		name     string
		domain   string
		event    string
		expected string
	}{

		{"Test 1: Subdomain", "owasp.org", "subdomain.owasp.org", "subdomain.owasp.org"},
		{"Test 2: Nested subdomain", "owasp.org", "sub.subdomain.owasp.org", "sub.subdomain.owasp.org"},
		{"Test 3: Subdomain-dashes", "owasp.org", "sub-domain.owasp.org", "sub-domain.owasp.org"},
		{"Test 4: Subdomain-dashes again", "owasp.org", "sub-d.sub-domain.owasp.org", "sub-d.sub-domain.owasp.org"},
		{"Test 5: Double period", "owasp.org", "sub..owasp.org", ""},
		{"Test 6: Wrong domain", "owasp.org", ".sub-d.sub-domain.owasp.com", ""},
		{"Test 7: Sub end with dash", "owasp.org", "sub-.owasp.org", ""},
	}
	for _, tt := range tests {
		s := SubdomainRegex(tt.domain)
		result := s.FindString(tt.event)
		if result != tt.expected {
			t.Errorf("Error Event %s: regex did not match %s", tt.name, tt.event)

		}

	}
}

func TestRemoveAsteriskLabel(t *testing.T) {
	tests := []struct {
		name     string
		event    string
		expected string
	}{

		{"Test 1: Subdomain", "*.subdomain.owasp.org", "subdomain.owasp.org"},
		{"Test 2: Nested subdomain", "*.subdomain.owasp.org", "subdomain.owasp.org"},
		{"Test 3: Subdomain-dashes", "*.sub-domain.owasp.org", "sub-domain.owasp.org"},
		{"Test 4: Subdomain-dashes", "*.sub-d.sub-domain.owasp.org", "sub-d.sub-domain.owasp.org"},
		{"Test 5: Middle Label Asterisk", "sub-d.sub-domain.*.owasp.org", "owasp.org"},
		{"Test 6: Missing Asterisk Label", "sub-domain.owasp.org", "sub-domain.owasp.org"},
		{"Test 7: Empty string", "", ""},
	}
	for _, tt := range tests {
		s := RemoveAsteriskLabel(tt.event)
		if s != tt.expected && s != "" {
			t.Errorf("Error Event %s: was expecting \"\" or %s, got %s", tt.name, tt.expected, tt.event)
		}
	}
}
