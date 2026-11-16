// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// tier is the access level a model-facing capability needs. A read tier
// capability is served to every client; an operator tier capability only to
// a client that presented the operator token, so the tier, not which code
// path registered the tool, decides who may call it.
type tier int

const (
	tierRead tier = iota
	tierOperator
)

// capability is one tool the model can call. Every model-facing tool — the
// graph reads, the investigation tools, the footprint drawing, the operator
// actions and, ahead, the config assistant — is declared as a capability so
// there is one registration path, one dispatch, and the access tier is a
// property of the tool rather than a function of where it was wired.
type capability struct {
	tool   *mcp.Tool
	tier   tier
	handle func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error)
}

// availableTo reports whether a connection may be served this capability. A
// read tier capability is always available; an operator tier one only in
// operator mode, so an operator action can never reach a read-only client.
func (c capability) availableTo(operator bool) bool {
	return c.tier != tierOperator || operator
}

// registerCapabilities adds each capability the connection may use to the
// server through one path.
func registerCapabilities(server *mcp.Server, caps []capability, operator bool) {
	for _, c := range caps {
		if !c.availableTo(operator) {
			continue
		}

		server.AddTool(c.tool, c.handle)
	}
}

// readCapabilities are the read-only tools: the graph and investigation
// tools dispatched by name, each run under its own timeout, with a tool
// failure returned as a result the model can read rather than a protocol
// error.
func readCapabilities(runner ai.ToolRunner, model llm.Model, store *ai.EvidenceStore) []capability {
	var caps []capability
	for _, spec := range toolSpecs(runner) {
		name := spec.Name
		caps = append(caps, capability{
			tool: &mcp.Tool{Name: name, Description: spec.Description, InputSchema: spec.Parameters},
			tier: tierRead,
			handle: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				var args json.RawMessage
				if req.Params != nil {
					args = req.Params.Arguments
				}

				ctx, cancel := context.WithTimeout(ctx, ai.ToolTimeout(name))
				defer cancel()

				result, err := runTool(ctx, runner, model, store, name, args)
				if err != nil {
					return &mcp.CallToolResult{IsError: true,
						Content: []mcp.Content{&mcp.TextContent{Text: err.Error()}}}, nil
				}

				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(result)}}}, nil
			},
		})
	}

	return caps
}
