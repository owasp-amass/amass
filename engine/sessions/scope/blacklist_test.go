// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"testing"
	"time"

	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

func TestAddBlacklist(t *testing.T) {
	s := New(time.Now())

	s.AddBlacklist("blocked.example.com")
	s.AddBlacklist("evil.test.org")

	if len(s.blacklist) != 2 {
		t.Errorf("Expected 2 entries in blacklist, got %d", len(s.blacklist))
	}

	if !s.blacklist["blocked.example.com"] {
		t.Error("Expected 'blocked.example.com' to be in blacklist")
	}

	if !s.blacklist["evil.test.org"] {
		t.Error("Expected 'evil.test.org' to be in blacklist")
	}
}

func TestIsBlacklisted(t *testing.T) {
	s := New(time.Now())

	s.AddBlacklist("blocked.example.com")
	s.AddBlacklist("evil.test.org")

	tests := []struct {
		name     string
		fqdn     string
		expected bool
	}{
		{"exact match", "blocked.example.com", true},
		{"subdomain of blacklisted", "sub.blocked.example.com", true},
		{"deep subdomain", "deep.sub.blocked.example.com", true},
		{"not blacklisted", "allowed.example.com", false},
		{"similar but not matching", "notblocked.example.com", false},
		{"different domain", "example.org", false},
		{"other blacklisted", "evil.test.org", true},
		{"subdomain of other blacklisted", "www.evil.test.org", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fqdn := &oamdns.FQDN{Name: tt.fqdn}
			result := s.IsBlacklisted(fqdn)
			if result != tt.expected {
				t.Errorf("IsBlacklisted(%s) = %v, expected %v", tt.fqdn, result, tt.expected)
			}
		})
	}
}

func TestIsAssetInScopeWithBlacklist(t *testing.T) {
	s := New(time.Now())

	// Add a domain to scope
	s.AddDomain("example.com")

	// Add a subdomain to blacklist
	s.AddBlacklist("blocked.example.com")

	// Test that normal subdomain is in scope
	normalFqdn := &oamdns.FQDN{Name: "allowed.example.com"}
	match, conf := s.IsAssetInScope(normalFqdn, 0)
	if match == nil || conf == 0 {
		t.Error("Expected 'allowed.example.com' to be in scope")
	}

	// Test that blacklisted subdomain is NOT in scope
	blockedFqdn := &oamdns.FQDN{Name: "blocked.example.com"}
	match, conf = s.IsAssetInScope(blockedFqdn, 0)
	if match != nil || conf != 0 {
		t.Error("Expected 'blocked.example.com' to NOT be in scope (blacklisted)")
	}

	// Test that subdomain of blacklisted is also NOT in scope
	subBlockedFqdn := &oamdns.FQDN{Name: "sub.blocked.example.com"}
	match, conf = s.IsAssetInScope(subBlockedFqdn, 0)
	if match != nil || conf != 0 {
		t.Error("Expected 'sub.blocked.example.com' to NOT be in scope (parent blacklisted)")
	}
}
