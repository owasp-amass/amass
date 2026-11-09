// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

func TestMCPList(t *testing.T) {
	input := strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25"}}` + "\n" + `{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n" + `{"jsonrpc":"2.0","id":2,"method":"tools/list"}` + "\n")
	var output bytes.Buffer
	server := Server{Runner: ai.ToolRunner{Limits: ai.DefaultLimits()}}
	if err := server.Serve(context.Background(), input, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "walk_relations") {
		t.Fatalf("tools not listed: %s", output.String())
	}
}
