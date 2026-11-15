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
