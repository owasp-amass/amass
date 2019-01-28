package utils

import (
	"fmt"
	"testing"
)

func TestSubdomainRegex(t *testing.T) {
	//use structs and arrays to make a table of test cases, lead with a name to call the test and then parameters for testing
	tests := []struct {
		name     string
		domain   string
		event    string
		expected string
	}{

		{"subdomain", "owasp.org", "subdomain.owasp.org", "subdomain.owasp.org"},
		{"nested subdomain", "owasp.org", "sub.subdomain.owasp.org", "sub.subdomain.owasp.org"},
		{"subdomain-dashes", "owasp.org", "sub-domain.owasp.org", "sub-domain.owasp.org"},
		{"subdomain-dashes", "owasp.org", "sub-d.sub-domain.owasp.org", "sub-d.sub-domain.owasp.org"},
		{"double period", "owasp.org", "sub..owasp.org", ""},
		{"wrong domain", "owasp.org", ".sub-d.sub-domain.owasp.com", ""},
		{"sub end with dash", "owasp.org", "sub-.owasp.org", ""},
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

		{"subdomain", "*.subdomain.owasp.org", "subdomain.owasp.org"},
		{"nested subdomain", "*.subdomain.owasp.org", "subdomain.owasp.org"},
		{"subdomain-dashes", "*.sub-domain.owasp.org", "sub-domain.owasp.org"},
		{"subdomain-dashes", "*.sub-d.sub-domain.owasp.org", "sub-d.sub-domain.owasp.org"},
	}
	for _, tt := range tests {
		s := RemoveAsteriskLabel(tt.event)
		if s != tt.expected && s != "" {
			t.Errorf("Error Event %s: was expecting \"\" or %s, got %s", tt.name, tt.expected, tt.event)
		}

	}

}
