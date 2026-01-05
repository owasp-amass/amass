// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package enum

import (
	"testing"

	"github.com/owasp-amass/amass/v5/config"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
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
