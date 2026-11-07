// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"testing"

	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

func TestAddBlacklist(t *testing.T) {
	s := New(nil).(*Scope)

	s.AddBlacklist("blocked.example.com")
	s.AddBlacklist("evil.test.org")

	if !s.IsBlacklisted(&oamdns.FQDN{Name: "blocked.example.com"}) {
		t.Error("Expected 'blocked.example.com' to be in blacklist")
	}

	if !s.IsBlacklisted(&oamdns.FQDN{Name: "evil.test.org"}) {
		t.Error("Expected 'evil.test.org' to be in blacklist")
	}
}

func TestIsBlacklisted(t *testing.T) {
	s := New(nil).(*Scope)

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

func TestIsBlacklistedVariousAssetTypes(t *testing.T) {
	s := New(nil).(*Scope)
	s.AddBlacklist("blocked.example.com")

	// URL tests
	if !s.IsBlacklisted(&oamurl.URL{Host: "blocked.example.com", Raw: "https://blocked.example.com"}) {
		t.Error("Expected URL with blacklisted host to be blacklisted")
	}
	if !s.IsBlacklisted(&oamurl.URL{Host: "sub.blocked.example.com", Raw: "https://sub.blocked.example.com"}) {
		t.Error("Expected URL with blacklisted subdomain host to be blacklisted")
	}
	if s.IsBlacklisted(&oamurl.URL{Host: "allowed.example.com", Raw: "https://allowed.example.com"}) {
		t.Error("Expected URL with allowed host to NOT be blacklisted")
	}

	// Email Identifier tests
	if !s.IsBlacklisted(&oamgen.Identifier{Type: oamgen.EmailAddress, ID: "user@blocked.example.com"}) {
		t.Error("Expected Email with blacklisted domain to be blacklisted")
	}
	if !s.IsBlacklisted(&oamgen.Identifier{Type: oamgen.EmailAddress, ID: "admin@sub.blocked.example.com"}) {
		t.Error("Expected Email with blacklisted subdomain to be blacklisted")
	}
	if s.IsBlacklisted(&oamgen.Identifier{Type: oamgen.EmailAddress, ID: "user@allowed.example.com"}) {
		t.Error("Expected Email with allowed domain to NOT be blacklisted")
	}

	// DomainRecord tests
	if !s.IsBlacklisted(&oamreg.DomainRecord{Domain: "blocked.example.com"}) {
		t.Error("Expected DomainRecord with blacklisted domain to be blacklisted")
	}
	if !s.IsBlacklisted(&oamreg.DomainRecord{Domain: "sub.blocked.example.com"}) {
		t.Error("Expected DomainRecord with blacklisted subdomain to be blacklisted")
	}
	if s.IsBlacklisted(&oamreg.DomainRecord{Domain: "allowed.example.com"}) {
		t.Error("Expected DomainRecord with allowed domain to NOT be blacklisted")
	}

	// TLSCertificate tests
	if !s.IsBlacklisted(&oamcert.TLSCertificate{SubjectCommonName: "blocked.example.com"}) {
		t.Error("Expected TLSCertificate with blacklisted SubjectCommonName to be blacklisted")
	}
	if !s.IsBlacklisted(&oamcert.TLSCertificate{SubjectCommonName: "sub.blocked.example.com"}) {
		t.Error("Expected TLSCertificate with blacklisted subdomain SubjectCommonName to be blacklisted")
	}
	if s.IsBlacklisted(&oamcert.TLSCertificate{SubjectCommonName: "allowed.example.com"}) {
		t.Error("Expected TLSCertificate with allowed SubjectCommonName to NOT be blacklisted")
	}
}

func TestIsAssetInScopeWithBlacklist(t *testing.T) {
	s := New(nil).(*Scope)

	// Add domain to scope
	s.AddDomain("example.com")

	// Add subdomain to blacklist
	s.AddBlacklist("blocked.example.com")

	// Test FQDN in scope vs blacklisted
	normalFqdn := &oamdns.FQDN{Name: "allowed.example.com"}
	match, conf := s.IsAssetInScope(normalFqdn, 0)
	if match == nil || conf == 0 {
		t.Error("Expected 'allowed.example.com' to be in scope")
	}

	blockedFqdn := &oamdns.FQDN{Name: "blocked.example.com"}
	match, conf = s.IsAssetInScope(blockedFqdn, 0)
	if match != nil || conf != 0 {
		t.Error("Expected 'blocked.example.com' to NOT be in scope (blacklisted)")
	}

	subBlockedFqdn := &oamdns.FQDN{Name: "sub.blocked.example.com"}
	match, conf = s.IsAssetInScope(subBlockedFqdn, 0)
	if match != nil || conf != 0 {
		t.Error("Expected 'sub.blocked.example.com' to NOT be in scope (parent blacklisted)")
	}

	// Test URL in scope vs blacklisted
	normalURL := &oamurl.URL{Host: "allowed.example.com", Raw: "https://allowed.example.com"}
	match, conf = s.IsAssetInScope(normalURL, 0)
	if match == nil || conf == 0 {
		t.Error("Expected URL 'https://allowed.example.com' to be in scope")
	}

	blockedURL := &oamurl.URL{Host: "blocked.example.com", Raw: "https://blocked.example.com"}
	match, conf = s.IsAssetInScope(blockedURL, 0)
	if match != nil || conf != 0 {
		t.Error("Expected URL 'https://blocked.example.com' to NOT be in scope (blacklisted)")
	}

	// Test Email in scope vs blacklisted
	normalEmail := &oamgen.Identifier{Type: oamgen.EmailAddress, ID: "user@allowed.example.com"}
	match, conf = s.IsAssetInScope(normalEmail, 0)
	if match == nil || conf == 0 {
		t.Error("Expected Email 'user@allowed.example.com' to be in scope")
	}

	blockedEmail := &oamgen.Identifier{Type: oamgen.EmailAddress, ID: "user@blocked.example.com"}
	match, conf = s.IsAssetInScope(blockedEmail, 0)
	if match != nil || conf != 0 {
		t.Error("Expected Email 'user@blocked.example.com' to NOT be in scope (blacklisted)")
	}

	// Test DomainRecord in scope vs blacklisted
	normalRecord := &oamreg.DomainRecord{Domain: "allowed.example.com"}
	match, conf = s.IsAssetInScope(normalRecord, 0)
	if match == nil || conf == 0 {
		t.Error("Expected DomainRecord 'allowed.example.com' to be in scope")
	}

	blockedRecord := &oamreg.DomainRecord{Domain: "blocked.example.com"}
	match, conf = s.IsAssetInScope(blockedRecord, 0)
	if match != nil || conf != 0 {
		t.Error("Expected DomainRecord 'blocked.example.com' to NOT be in scope (blacklisted)")
	}

	// Test TLSCertificate in scope vs blacklisted
	normalCert := &oamcert.TLSCertificate{SubjectCommonName: "allowed.example.com"}
	match, conf = s.IsAssetInScope(normalCert, 0)
	if match == nil || conf == 0 {
		t.Error("Expected TLSCertificate 'allowed.example.com' to be in scope")
	}

	blockedCert := &oamcert.TLSCertificate{SubjectCommonName: "blocked.example.com"}
	match, conf = s.IsAssetInScope(blockedCert, 0)
	if match != nil || conf != 0 {
		t.Error("Expected TLSCertificate 'blocked.example.com' to NOT be in scope (blacklisted)")
	}
}

func TestScopeAddBlacklistedAsset(t *testing.T) {
	s := New(nil).(*Scope)
	s.AddBlacklist("blocked.example.com")

	// Adding blacklisted FQDN directly should be rejected
	if s.AddFQDN(&oamdns.FQDN{Name: "blocked.example.com"}) {
		t.Error("Expected AddFQDN with blacklisted domain to return false")
	}

	if s.Add(&oamdns.FQDN{Name: "blocked.example.com"}) {
		t.Error("Expected Add with blacklisted domain to return false")
	}

	if s.Add(&oamurl.URL{Host: "blocked.example.com"}) {
		t.Error("Expected Add with blacklisted URL to return false")
	}

	if s.Add(&oamreg.DomainRecord{Domain: "blocked.example.com"}) {
		t.Error("Expected Add with blacklisted DomainRecord to return false")
	}

	// Adding allowed domain should succeed
	if !s.AddDomain("example.com") {
		t.Error("Expected AddDomain with allowed domain to return true")
	}
}
