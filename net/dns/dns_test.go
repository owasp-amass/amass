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

		if result := s.FindString(tt.event); result != tt.expected {
			t.Errorf("Error Event %s: regex did not match %s", tt.name, tt.event)

		}
	}
}

func TestAnySubdomainRegex(t *testing.T) {
	tests := []struct {
		Value    string
		Expected bool
	}{
		{"owasp.org", true},
		{"subdomain.owasp.org", true},
		{"sub-domain.owasp.org", true},
		{"subdomain.owasp.", false},
		{"sub..owasp.org", false},
		{".sub-d.sub-domain.owasp.com", false},
		{"sub-.owasp.org", false},
	}

	re := AnySubdomainRegex()
	for _, test := range tests {
		loc := re.FindStringIndex(test.Value)

		if loc == nil || (test.Value[loc[0]:loc[1]] == test.Value) != test.Expected {
			t.Errorf("The regexp did not match %s as expected", test.Value)
		}
	}
}

func TestCopyString(t *testing.T) {
	tests := []string{"", "owasp.org", "TESTING"}

	for _, test := range tests {
		if c := CopyString(test); c != test {
			t.Errorf("Returned %s instead of %s", c, test)
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
		if s := RemoveAsteriskLabel(tt.event); s != tt.expected && s != "" {
			t.Errorf("Error Event %s: was expecting \"\" or %s, got %s", tt.name, tt.expected, tt.event)
		}
	}
}

func TestReverseString(t *testing.T) {
	tests := []struct {
		Value    string
		Expected string
	}{
		{"owasp", "psawo"},
		{"Test", "tseT"},
		{"*.sub-d.sub-domain.owasp.org", "gro.psawo.niamod-bus.d-bus.*"},
	}

	for _, test := range tests {
		if c := ReverseString(test.Value); c != test.Expected {
			t.Errorf("Returned %s instead of %s", c, test.Expected)
		}
	}
}

func TestReverseIP(t *testing.T) {
	tests := []struct {
		Address  string
		Expected string
	}{
		{"72.237.4.0", "0.4.237.72"},
		{"192.168.1.0", "0.1.168.192"},
		{"174.129.0.0", "0.0.129.174"},
		{"0.0.0.0", "0.0.0.0"},
	}

	for _, test := range tests {
		if r := ReverseIP(test.Address); r != test.Expected {
			t.Errorf("%s caused %s to be returned instead of %s", test.Address, r, test.Expected)
		}
	}
}

func TestIPv6NibbleFormat(t *testing.T) {
	tests := []struct {
		Address  string
		Expected string
	}{
		{"2620:0:860:2::", "0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.2.0.0.0.0.6.8.0.0.0.0.0.0.2.6.2"},
		{"2620:0:860:2:ffff:ffff:ffff:ffff", "f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.f.2.0.0.0.0.6.8.0.0.0.0.0.0.2.6.2"},
		{"fdda:5cc1:23:4::1f", "f.1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.4.0.0.0.3.2.0.0.1.c.c.5.a.d.d.f"},
	}

	for _, test := range tests {
		if r := IPv6NibbleFormat(test.Address); r != test.Expected {
			t.Errorf("%s caused %s to be returned instead of %s", test.Address, r, test.Expected)
		}
	}
}

func TestExpandIPv6Addr(t *testing.T) {
	tests := []struct {
		Address  string
		Expected string
	}{
		{"2620:0:860:2::", "2620:0000:0860:0002:0000:0000:0000:0000"},
		{"fdda:5cc1:23:4::1f", "fdda:5cc1:0023:0004:0000:0000:0000:001f"},
		{"2620:0:860:2:ffff:ffff:ffff:ffff", "2620:0000:0860:0002:ffff:ffff:ffff:ffff"},
	}

	for _, test := range tests {
		if r := expandIPv6Addr(test.Address); r != test.Expected {
			t.Errorf("%s caused %s to be returned instead of %s", test.Address, r, test.Expected)
		}
	}
}
