// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestMakeAssetsWithProvidedNames(t *testing.T) {
	cfg := config.NewConfig()

	// Add a domain to scope
	cfg.AddDomain("example.com")

	// Add provided names (simulating -nf flag)
	cfg.ProvidedNames = []string{
		"known.example.com",
		"discovered.example.com",
		"api.example.com",
	}

	assets := convertScopeToAssets(cfg.Scope)

	// Should have 1 domain, not 4 assets
	if len(assets) != 1 {
		t.Errorf("Expected 1 asset, got %d", len(assets))
	}

	// Verify that provided names are included as FQDNs
	foundNames := make(map[string]bool)
	for _, asset := range assets {
		if fqdn, ok := asset.(oamdns.FQDN); ok {
			foundNames[fqdn.Name] = true
		}
	}

	expectedNames := []string{"example.com"}
	for _, name := range expectedNames {
		if !foundNames[name] {
			t.Errorf("Expected to find %s in assets", name)
		}
	}
}

func TestMakeAssetsWithoutProvidedNames(t *testing.T) {
	cfg := config.NewConfig()

	// Add only a domain to scope (no provided names)
	cfg.AddDomain("example.com")

	assets := convertScopeToAssets(cfg.Scope)

	// Should have only 1 domain
	if len(assets) != 1 {
		t.Errorf("Expected 1 asset, got %d", len(assets))
	}
}

func TestConvertScopeToAssetsOrganizations(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Scope.Domains = []string{"example.com"}
	cfg.Scope.ASNs = []int{64496}
	cfg.Scope.Organizations = []string{"Example Corporation"}

	var orgs, domains, asns int
	for _, a := range convertScopeToAssets(cfg.Scope) {
		switch v := a.(type) {
		case oamorg.Organization:
			orgs++
			if v.Name != "Example Corporation" {
				t.Errorf("organization name = %q", v.Name)
			}
		case oamdns.FQDN:
			domains++
		case oamnet.AutonomousSystem:
			asns++
		}
	}
	// Previously supported entry types still convert, alongside the new
	// organization.
	if orgs != 1 || domains != 1 || asns != 1 {
		t.Errorf("orgs=%d domains=%d asns=%d", orgs, domains, asns)
	}
}
