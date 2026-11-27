// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
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
//
// A capability sets exactly one of handle and approve. handle runs the tool
// directly. approve declares that the action always needs the user's consent:
// it validates the request and returns the message to show and the act to
// carry out, and the framework — not the handler — passes both to the
// operator's gate, so an action that writes or collects cannot be registered
// without its approval step.
type capability struct {
	tool   *mcp.Tool
	tier   tier
	handle func(context.Context, *mcp.CallToolRequest) (*mcp.CallToolResult, error)
	// approve validates the call and returns the approval message and the act
	// to run once the user approves, or an error to return to the model. It is
	// used only by operator tier capabilities, where gate is available.
	approve func(context.Context, *mcp.CallToolRequest, json.RawMessage) (string,
		func(via string) (*mcp.CallToolResult, error), error)
}

// availableTo reports whether a connection may be served this capability. A
// read tier capability is always available; an operator tier one only in
// operator mode, so an operator action can never reach a read-only client.
func (c capability) availableTo(operator bool) bool {
	return c.tier != tierOperator || operator
}

// registerCapabilities adds each capability the connection may use to the
// server through one path. op is the operator the connection acts as, or nil
// for a read-only connection; it decides which capabilities are available and
// enforces the approval step for the ones that declare it.
func registerCapabilities(server *mcp.Server, caps []capability, op *Operator) {
	for _, c := range caps {
		if !c.availableTo(op != nil) {
			continue
		}
		if c.approve != nil {
			if op == nil {
				// An approval-gated capability cannot run without an operator to
				// gate it; availableTo keeps this from happening.
				continue
			}

			approve := c.approve
			server.AddTool(c.tool, func(ctx context.Context,
				req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
				args := toolArgs(req)

				msg, act, err := approve(ctx, req, args)
				if err != nil {
					return errorResult(err), nil
				}

				// gate returns the elicitation request (first call) or the act's
				// result; a refusal or a failed action comes back as an error,
				// which the model reads as a tool result, not a protocol error.
				res, err := op.gate(req, msg, act)
				if err != nil {
					return errorResult(err), nil
				}

				return res, nil
			})
			continue
		}

		server.AddTool(c.tool, c.handle)
	}
}

// toolArgs are a call's arguments, an empty object when the client sent
// none: a tool without parameters is often called with no arguments at all,
// which would otherwise read as truncated JSON (EOF).
func toolArgs(req *mcp.CallToolRequest) json.RawMessage {
	if req == nil || req.Params == nil {
		return json.RawMessage("{}")
	}
	args := bytes.TrimSpace(req.Params.Arguments)
	if len(args) == 0 || bytes.Equal(args, []byte("null")) {
		return json.RawMessage("{}")
	}
	return args
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
				args := toolArgs(req)

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
