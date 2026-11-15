// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net"
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

// Organizations are a scope boundary and merge from the seed like other
// entries.
func TestScopeAndSeedOrganizations(t *testing.T) {
	c := loadYAML(t, `seed:
  organizations:
    - Example Holdings LLC
scope:
  organizations:
    - Example Corporation
`)
	if !slices.Contains(c.Scope.Organizations, "Example Corporation") ||
		!slices.Contains(c.Scope.Organizations, "Example Holdings LLC") {
		t.Errorf("scope organizations = %v", c.Scope.Organizations)
	}
	if !slices.Equal(c.Seed.Organizations, []string{"Example Holdings LLC"}) {
		t.Errorf("seed organizations = %v", c.Seed.Organizations)
	}
}

// Seed DNS names are leads: they become provided names, and each lead's
// registered domain joins the scope boundary so it is never dropped as out
// of scope. The lead's registered domain is not, on its own, a seed.
func TestSeedNamesAreLeads(t *testing.T) {
	dir := t.TempDir()
	namesFile := filepath.Join(dir, "leads.txt")
	if err := os.WriteFile(namesFile, []byte("vpn.corp.example.com\n# comment\napi.example.net\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	c := loadYAML(t, `seed:
  domains:
    - example.com
  names:
    - mail.example.com
  names_file: `+namesFile+`
`)
	for _, want := range []string{"mail.example.com", "vpn.corp.example.com", "api.example.net"} {
		if !slices.Contains(c.ProvidedNames, want) {
			t.Errorf("provided names %v lack %q", c.ProvidedNames, want)
		}
	}
	// The registered domains of the leads are in the scope boundary.
	for _, want := range []string{"example.com", "example.net"} {
		if !c.IsDomainInScope("x." + want) {
			t.Errorf("registered domain %q is not in scope; scope domains = %v", want, c.Scope.Domains)
		}
	}
	// The seed's own start is its domains, not the leads' registered domains.
	if !slices.Equal(c.Seed.Domains, []string{"example.com"}) {
		t.Errorf("seed start = %v, expected only the seed domain", c.Seed.Domains)
	}
}

// AddSeedNames also serves the -nf flag after the config is loaded.
func TestAddSeedNamesFromFlag(t *testing.T) {
	c := NewConfig()
	c.Scope.Domains = []string{"example.com"}
	c.AddSeedNames("lead.sub.example.com", "")

	if !slices.Contains(c.ProvidedNames, "lead.sub.example.com") {
		t.Errorf("provided names = %v", c.ProvidedNames)
	}
	if !c.IsDomainInScope("another.example.com") {
		t.Errorf("the lead's registered domain is not in scope: %v", c.Scope.Domains)
	}
}

// SeedScope is where the run starts: the whole scope when no seed was given
// (the command-line / flag case with no config seed section), and the seed
// itself when one was configured.
func TestSeedScopeStart(t *testing.T) {
	// Flag-only style: no seed, domains added to the scope after load.
	c := NewConfig()
	c.AddDomain("example.com")
	if start := c.SeedScope(); start != c.Scope || !slices.Equal(start.Domains, []string{"example.com"}) {
		t.Errorf("with no seed, the start should be the scope: %+v", start)
	}

	// Explicit seed: the start is the seed, not the wider scope.
	c2 := loadYAML(t, `seed:
  domains:
    - start.example.com
scope:
  domains:
    - wider.example.net
`)
	start := c2.SeedScope()
	if !slices.Contains(start.Domains, "start.example.com") || slices.Contains(start.Domains, "wider.example.net") {
		t.Errorf("the start should be the seed only: %v", start.Domains)
	}
	if !c2.IsDomainInScope("x.wider.example.net") {
		t.Error("the wider scope domain should still bound the run")
	}
}

// HasSeed is satisfied by any kind of starting point, not only domains, so
// an organization, address, CIDR, ASN or provided name can seed a run.
func TestHasSeed(t *testing.T) {
	if (&Config{Scope: &Scope{}, Seed: &Scope{}}).HasSeed() {
		t.Error("an empty configuration should have no seed")
	}

	cases := []func(*Config){
		func(c *Config) { c.Scope.Organizations = []string{"Example Corporation"} },
		func(c *Config) { c.Scope.ASNs = []int{64496} },
		func(c *Config) { c.Scope.Addresses = []net.IP{net.ParseIP("192.0.2.1")} },
		func(c *Config) { c.ProvidedNames = []string{"lead.example.com"} },
	}
	for i, set := range cases {
		c := &Config{Scope: &Scope{}, Seed: &Scope{}}
		set(c)
		if !c.HasSeed() {
			t.Errorf("case %d: expected a seed", i)
		}
	}
}
