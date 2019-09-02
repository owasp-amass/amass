// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dns

import (
	"testing"
)

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
	}
	for _, tt := range tests {
		s := RemoveAsteriskLabel(tt.event)
		if s != tt.expected && s != "" {
			t.Errorf("Error Event %s: was expecting \"\" or %s, got %s", tt.name, tt.expected, tt.event)
		}
	}
}
