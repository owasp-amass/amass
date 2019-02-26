package sources

import "testing"

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
