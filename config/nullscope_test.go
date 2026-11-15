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

// A scope section whose entries are all commented out restricts nothing
// and probes the default ports.
func TestEmptyScopeSectionUsesDefaultPorts(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := "scope:\n#  domains:\n#    - owasp.org\n#  ports:\n#    - 443\noptions:\n  resolvers:\n    - 8.8.8.8\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewConfig()
	if err := c.LoadSettings(p); err != nil {
		t.Fatal(err)
	}
	if c.Scope == nil || !slices.Equal(c.Scope.Ports, DefaultPorts) {
		t.Fatalf("scope = %+v", c.Scope)
	}
}

// Listed ports replace the defaults.
func TestListedPortsReplaceDefaults(t *testing.T) {
	p := filepath.Join(t.TempDir(), "config.yaml")
	data := "scope:\n  domains:\n    - owasp.org\n  ports:\n    - 22\n    - 443\n"
	if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}

	c := NewConfig()
	if err := c.LoadSettings(p); err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(c.Scope.Ports, []int{22, 443}) {
		t.Fatalf("ports = %v", c.Scope.Ports)
	}
}

// The embedded default configuration must load and parse: it ships with
// Amass and is the template users copy.
func TestDefaultConfigLoads(t *testing.T) {
	c := NewConfig()
	if err := c.LoadSettings("../resources/config.yaml"); err != nil {
		t.Fatalf("the default config did not load: %v", err)
	}
	if !slices.Equal(c.Scope.Ports, []int{80, 443, 8000, 8080, 8443, 8888}) {
		t.Errorf("default ports = %v", c.Scope.Ports)
	}
	// Every seed/scope entry is commented out, so the scope restricts nothing
	// and the seed falls back to it.
	if c.Seed != c.Scope {
		t.Error("with no seed section, the seed should be the scope")
	}
}
