// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"testing"
)

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
