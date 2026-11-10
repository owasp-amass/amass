// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"context"
	"io"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// exchange runs a stdio session like a client: it sends requests one at a
// time, waits for each reply, then closes stdin and returns all output.
func exchange(t *testing.T, server Server, requests ...string) string {
	t.Helper()

	inR, inW := io.Pipe()
	outR, outW := io.Pipe()
	done := make(chan error, 1)
	go func() {
		done <- server.Serve(context.Background(), inR, outW)
		_ = outW.Close()
	}()

	lines := bufio.NewScanner(outR)
	lines.Buffer(make([]byte, 1<<20), 8<<20)
	var out strings.Builder
	for _, req := range requests {
		if _, err := io.WriteString(inW, req+"\n"); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(req, `"id"`) {
			continue
		}
		if !lines.Scan() {
			t.Fatalf("no reply to %s: %v", req, lines.Err())
		}

		out.WriteString(lines.Text() + "\n")
	}

	_ = inW.Close()
	go func() {
		for lines.Scan() {
		}
	}()
	if err := <-done; err != nil {
		t.Fatalf("Serve: %v", err)
	}

	return out.String()
}

const (
	initRequest = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",` +
		`"capabilities":{},"clientInfo":{"name":"test","version":"1"}}}`
	initializedNote = `{"jsonrpc":"2.0","method":"notifications/initialized"}`
	listRequest     = `{"jsonrpc":"2.0","id":2,"method":"tools/list"}`
)

func TestMCPList(t *testing.T) {
	out := exchange(t, Server{Runner: ai.ToolRunner{Limits: ai.DefaultLimits()}}, initRequest, initializedNote,
		listRequest)
	if !strings.Contains(out, "walk_relations") {
		t.Fatalf("tools not listed: %s", out)
	}
}

type nodeCatalog struct{}

func (nodeCatalog) Relations() []ai.RelationshipSchema {
	return []ai.RelationshipSchema{
		{SourceType: "FQDN", Label: "node", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	}
}

// With a catalog, the investigation tools are listed with the graph tools.
func TestMCPListsInvestigationTools(t *testing.T) {
	out := exchange(t, Server{Runner: ai.ToolRunner{Limits: ai.DefaultLimits(), Catalog: nodeCatalog{}}},
		initRequest, initializedNote, listRequest)
	for _, name := range []string{`"name":"investigate"`, `"name":"verify_citations"`, `"name":"walk_relations"`} {
		if !strings.Contains(out, name) {
			t.Errorf("tools/list lacks %s", name)
		}
	}
}

// A tool failure is a result the client can read, not a protocol error.
func TestMCPToolErrorsAreResults(t *testing.T) {
	out := exchange(t, Server{Runner: ai.ToolRunner{Limits: ai.DefaultLimits(), Catalog: nodeCatalog{}}},
		initRequest, initializedNote,
		`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"verify_citations",`+
			`"arguments":{"investigation_id":"inv-none","text":"x [E1]."}}}`)
	if !strings.Contains(out, `"isError":true`) || !strings.Contains(out, "unknown or expired investigation_id") {
		t.Fatalf("tool error not returned as a result: %s", out)
	}
}
