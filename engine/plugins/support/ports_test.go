// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

func TestScopePortsAndClaims(t *testing.T) {
	cfg := config.NewConfig()
	cfg.Scope.Ports = []int{80, 22, 443, 25, 8443}

	if got := ScopePorts(cfg, []int{22, 2222}); !slices.Equal(got, []int{22}) {
		t.Fatalf("ScopePorts = %v, want [22]", got)
	}
	if got := ScopePorts(cfg, []int{21, 110}); len(got) != 0 {
		t.Fatalf("ScopePorts = %v, want none", got)
	}

	ClaimPorts("test", 22, 25)
	if got := HTTPPorts(cfg); !slices.Equal(got, []int{80, 443, 8443}) {
		t.Fatalf("HTTPPorts = %v, want [80 443 8443]", got)
	}
	if ScopePorts(nil, []int{22}) != nil || HTTPPorts(nil) != nil {
		t.Fatal("a nil config has no ports")
	}
}
