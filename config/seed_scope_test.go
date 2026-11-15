// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func loadYAML(t *testing.T, data string) *Config {
	t.Helper()
	p := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewConfig()
	if err := c.LoadSettings(p); err != nil {
		t.Fatal(err)
	}

	return c
}

// A seed with no scope section bounds the run by its own entries, with the
// default ports.
func TestSeedOnlyBecomesScope(t *testing.T) {
	c := loadYAML(t, "seed:\n  domains:\n    - example.com\n  cidrs:\n    - 192.0.2.0/24\n")
	if !slices.Equal(c.Scope.Domains, []string{"example.com"}) || len(c.Scope.CIDRs) != 1 {
		t.Errorf("scope = %+v", c.Scope)
	}
	if !slices.Equal(c.Scope.Ports, DefaultPorts) {
		t.Errorf("ports = %v, want the defaults", c.Scope.Ports)
	}
}

// A seed and a scope section are both kept: the scope is their union, with
// the scope section's ports and blacklist.
func TestSeedAndScopeAreBothKept(t *testing.T) {
	c := loadYAML(t, `seed:
  domains:
    - example.com
scope:
  domains:
    - example.org
    - EXAMPLE.com
  cidrs:
    - 198.51.100.0/24
  asns:
    - 64496
  blacklist:
    - internal.example.org
  ports:
    - 22
    - 443
`)
	if !slices.Equal(c.Scope.Domains, []string{"example.org", "EXAMPLE.com"}) {
		t.Errorf("domains = %v; the seed's name is already in scope", c.Scope.Domains)
	}
	if len(c.Scope.CIDRs) != 1 || !slices.Equal(c.Scope.ASNs, []int{64496}) ||
		!slices.Equal(c.Scope.Blacklist, []string{"internal.example.org"}) {
		t.Errorf("the scope section was not kept: %+v", c.Scope)
	}
	if !slices.Equal(c.Scope.Ports, []int{22, 443}) {
		t.Errorf("ports = %v, want the scope section's", c.Scope.Ports)
	}
	if !slices.Equal(c.Seed.Domains, []string{"example.com"}) {
		t.Errorf("seed = %+v", c.Seed)
	}
}

// A seed outside the scope section's names is added to the scope, since the
// enumeration starts from it.
func TestSeedIsAddedToScope(t *testing.T) {
	c := loadYAML(t, `seed:
  domains:
    - example.com
  ips:
    - 192.0.2.1
scope:
  cidrs:
    - 198.51.100.0/24
`)
	if !slices.Equal(c.Scope.Domains, []string{"example.com"}) || len(c.Scope.Addresses) != 1 ||
		len(c.Scope.CIDRs) != 1 {
		t.Errorf("scope = %+v", c.Scope)
	}
	if !slices.Equal(c.Scope.Ports, DefaultPorts) {
		t.Errorf("ports = %v, want the defaults", c.Scope.Ports)
	}
}

// Without a seed, the scope section is used as written.
func TestScopeOnlyIsUnchanged(t *testing.T) {
	c := loadYAML(t, "scope:\n  domains:\n    - example.com\n  ports:\n    - 8443\n")
	if !slices.Equal(c.Scope.Domains, []string{"example.com"}) || !slices.Equal(c.Scope.Ports, []int{8443}) {
		t.Errorf("scope = %+v", c.Scope)
	}
	if c.Seed != c.Scope {
		t.Error("without a seed, the seed is the scope")
	}
}
