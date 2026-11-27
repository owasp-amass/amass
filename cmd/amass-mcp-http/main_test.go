// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"strings"
	"testing"
)

func TestTokens(t *testing.T) {
	strong := strings.Repeat("a", 32)
	other := strings.Repeat("b", 40)
	for name, c := range map[string]struct {
		token, op string
		ok        bool
	}{
		"read-only only":      {strong, "", true},
		"with operator":       {strong, other, true},
		"no token":            {"", "", false},
		"short token":         {strong[:31], "", false},
		"short operator":      {strong, other[:31], false},
		"operator same token": {strong, strong, false},
	} {
		getenv := func(k string) string {
			switch k {
			case "AMASS_MCP_TOKEN":
				return c.token
			case "AMASS_MCP_OPERATOR_TOKEN":
				return c.op
			}
			return ""
		}
		token, op, err := tokens(getenv)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok %v", name, err, c.ok)
			continue
		}
		if c.ok && (token != c.token || op != c.op) {
			t.Errorf("%s: tokens = %q, %q", name, token, op)
		}
	}
}
