// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestCapabilityAvailableTo(t *testing.T) {
	read := capability{tier: tierRead}
	oper := capability{tier: tierOperator}

	if !read.availableTo(false) || !read.availableTo(true) {
		t.Error("a read capability should be available to every connection")
	}
	if oper.availableTo(false) {
		t.Error("an operator capability must not be available without operator mode")
	}
	if !oper.availableTo(true) {
		t.Error("an operator capability should be available in operator mode")
	}
}

// A call with no arguments, as clients send for a tool without parameters,
// reads as an empty object rather than truncated JSON.
func TestToolArgsDefaultToAnEmptyObject(t *testing.T) {
	for _, in := range []json.RawMessage{nil, json.RawMessage(""), json.RawMessage(" null "), json.RawMessage("  ")} {
		req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: in}}
		if got := string(toolArgs(req)); got != "{}" {
			t.Errorf("arguments %q read as %q", in, got)
		}
	}
	if got := string(toolArgs(nil)); got != "{}" {
		t.Errorf("no request read as %q", got)
	}
	req := &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: json.RawMessage(`{"a":1}`)}}
	if got := string(toolArgs(req)); got != `{"a":1}` {
		t.Errorf("arguments read as %q", got)
	}
}
