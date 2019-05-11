package utils

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

func TestNewUniqueElements(t *testing.T) {
	tests := []struct {
		name     string
		orig     []string
		event    []string
		expected []string
	}{
		{"Test 1: Duplicate elements", []string{"sub1.owasp.org", "sub2.owasp.org", "sub3.owasp.org"}, []string{"sub4.owasp.org", "sub4.owasp.org"}, []string{"sub4.owasp.org"}},
		{"Test 2: Empty return", []string{"sub1.owasp.org", "sub2.owasp.org", "sub3.owasp.org"}, []string{"sub1.owasp.org"}, []string{}},
	}

	for _, tt := range tests {
		s := NewUniqueElements(tt.orig, tt.event...)
		for v := range s {
			if s[v] != tt.expected[v] {
				t.Errorf("Error Event %s: got %s, expected %s", tt.name, s, tt.expected)
			}

		}
	}
}

func TestUniqueAppend(t *testing.T) {
	tests := []struct {
		name     string
		orig     []string
		event    string
		expected []string
	}{
		{"Test 1: Duplicate elements", []string{"sub1.owasp.org", "sub2.owasp.org"}, "sub2.owasp.org", []string{"sub1.owasp.org", "sub2.owasp.org"}},
		{"Test 2: New element", []string{"sub1.owasp.org", "sub2.owasp.org", "sub3.owasp.org"}, "sub4.owasp.org", []string{"sub1.owasp.org", "sub2.owasp.org", "sub3.owasp.org", "sub4.owasp.org"}},
	}
	for _, tt := range tests {
		s := UniqueAppend(tt.orig, tt.event)
		i := 0
		for _, x := range s {
			if x != tt.expected[i] {
				t.Errorf("Error in %s, got %s, expected %s.", tt.name, x, tt.expected[i])
			}
			i++
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
	}
	for _, tt := range tests {
		s := RemoveAsteriskLabel(tt.event)
		if s != tt.expected && s != "" {
			t.Errorf("Error Event %s: was expecting \"\" or %s, got %s", tt.name, tt.expected, tt.event)
		}

	}

}
