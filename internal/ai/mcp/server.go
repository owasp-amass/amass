// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package mcp serves the read-only Amass AI tools over the Model Context
// Protocol using the official MCP Go SDK: over stdio (Server) and over
// Streamable HTTP behind Amass's own authentication and session limits
// (HTTPServer).
package mcp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"sync"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
)

// serverVersion is reported to MCP clients.
const serverVersion = "0.3.0"

// Server serves MCP over stdio. Model is optional: without it the
// investigate tool answers every kind except paths. Evidence keeps recent
// investigations for verify_citations; a nil store is created on Serve.
type Server struct {
	Runner   ai.ToolRunner
	Model    ai.Model
	Evidence *ai.EvidenceStore
}

// Serve runs one MCP session over in and out until the client disconnects
// or ctx ends.
func (s Server) Serve(ctx context.Context, in io.Reader, out io.Writer) error {
	if s.Evidence == nil {
		s.Evidence = ai.NewEvidenceStore()
	}

	server := newSDKServer(s.Runner, s.Model, s.Evidence)
	reader := &eofReader{Reader: in}
	err := server.Run(ctx, &mcp.IOTransport{Reader: io.NopCloser(reader), Writer: nopWriteCloser{out}})
	if err != nil && reader.closed() && ctx.Err() == nil {
		// The client closed stdin: the session ended normally. The SDK
		// reports this as its own closing error rather than io.EOF.
		return nil
	}

	return err
}

// eofReader records whether the client closed its end of the stream.
type eofReader struct {
	io.Reader
	mu  sync.Mutex
	eof bool
}

func (r *eofReader) Read(p []byte) (int, error) {
	n, err := r.Reader.Read(p)
	if errors.Is(err, io.EOF) {
		r.mu.Lock()
		r.eof = true
		r.mu.Unlock()
	}

	return n, err
}

func (r *eofReader) closed() bool {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.eof
}

type nopWriteCloser struct{ io.Writer }

func (nopWriteCloser) Close() error { return nil }

// newSDKServer builds an MCP server with every read-only tool: the graph
// tools and the investigation tools.
func newSDKServer(runner ai.ToolRunner, model ai.Model, store *ai.EvidenceStore) *mcp.Server {
	server := mcp.NewServer(&mcp.Implementation{Name: "amass-ai", Version: serverVersion},
		&mcp.ServerOptions{GetSessionID: newSessionID})
	for _, spec := range toolSpecs(runner) {
		name := spec.Name
		server.AddTool(&mcp.Tool{Name: name, Description: spec.Description, InputSchema: spec.Parameters},
			func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var args json.RawMessage
				if req.Params != nil {
					args = req.Params.Arguments
				}

				ctx, cancel := context.WithTimeout(ctx, ai.ToolTimeout(name))
				defer cancel()

				result, err := runTool(ctx, runner, model, store, name, args)
				if err != nil {
					// Tool failures are results the model can read, not protocol errors.
					return &mcp.CallToolResult{
							IsError: true,
							Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}},
						},
						nil
				}

				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil
			})
	}

	return server
}

// toolSpecs lists the graph tools and the investigation tools.
func toolSpecs(runner ai.ToolRunner) []ai.ToolSpec {
	return append(ai.Specs(), ai.InvestigationSpecs(runner.Catalog)...)
}

// runTool dispatches a tool call to the investigation tools or the runner.
func runTool(ctx context.Context, runner ai.ToolRunner, model ai.Model, store *ai.EvidenceStore, name string, args json.RawMessage) (json.RawMessage, error) {
	if ai.IsInvestigationTool(name) {
		return ai.RunInvestigationTool(ctx, runner, model, store, name, args)
	}

	return runner.Run(ctx, name, args)
}

// newSessionID returns 192 random bits, hex encoded, for HTTP sessions.
func newSessionID() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// An empty ID makes the SDK refuse the session rather than reuse one.
		return ""
	}

	return hex.EncodeToString(b)
}
