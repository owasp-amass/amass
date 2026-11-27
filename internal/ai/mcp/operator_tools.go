// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/secrets"
)

// operatorTools collects the operator tools as capabilities.
type operatorTools struct {
	op     *Operator
	runner ai.ToolRunner
	caps   []capability
}

// operatorCapabilities returns the operator tools as capabilities. Every one
// is operator tier, so the registry serves them only to a connection acting
// as an operator. The tools that collect data or write to the database declare
// their approval step (approve) rather than calling gate themselves, so the
// framework enforces consent; review_proposal keeps its own handler because it
// gates only the decisions that write (approve and retract), not a rejection.
func operatorCapabilities(op *Operator, runner ai.ToolRunner) []capability {
	t := &operatorTools{op: op, runner: runner}
	t.collectionTools()
	t.documentTools()
	t.reviewTools()
	t.contributeTools()
	t.dataSourceTools()
	return t.caps
}

// add declares a tool that runs directly; a handler error is returned to the
// model as a tool result, as before.
func (t *operatorTools) add(name, title, desc string, schema map[string]any, ann *mcp.ToolAnnotations,
	h func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error)) {
	ann.Title = title
	t.caps = append(t.caps, capability{tier: tierOperator,
		tool: &mcp.Tool{Name: name, Title: title, Description: desc, InputSchema: schema, Annotations: ann},
		handle: func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			res, err := h(ctx, req, toolArgs(req))
			if err != nil {
				return errorResult(err), nil
			}

			return res, nil
		}})
}

// approveAction declares a tool whose action always needs the user's
// consent: h validates the call and returns the approval message and the act
// to run, and the registry passes both to gate.
func (t *operatorTools) approveAction(name, title, desc string, schema map[string]any, ann *mcp.ToolAnnotations,
	h func(context.Context, *mcp.CallToolRequest, json.RawMessage) (string,
		func(via string) (*mcp.CallToolResult, error), error)) {
	ann.Title = title
	t.caps = append(t.caps, capability{tier: tierOperator,
		tool:    &mcp.Tool{Name: name, Title: title, Description: desc, InputSchema: schema, Annotations: ann},
		approve: h})
}

// obj is an object input schema with the given properties.
func obj(required []string, props map[string]any) map[string]any {
	schema := map[string]any{"type": "object", "properties": props, "additionalProperties": false}
	if len(required) > 0 {
		// Clients reject a null required list.
		schema["required"] = required
	}

	return schema
}

// readOnly annotates a tool that only reads.
func readOnly() *mcp.ToolAnnotations {
	return &mcp.ToolAnnotations{ReadOnlyHint: true, IdempotentHint: true, OpenWorldHint: boolPtr(false)}
}

// dataSourceTools are the tools for the engine's data sources and their keys.
func (t *operatorTools) dataSourceTools() {
	op := t.op

	t.add(ToolDataSources, "Amass data sources",
		"List the data sources the enumeration engine can use and whether each has credentials configured, "+
			"in the datasources file, the environment or the database's encrypted store. Never shows the credentials.",
		obj(nil, map[string]any{}), readOnly(),
		func(context.Context, *mcp.CallToolRequest, json.RawMessage) (*mcp.CallToolResult, error) {
			return dataSourceStatus(op)
		})

	t.add(ToolDataSourceKey, "Link to add a data source key",
		"Create a one-time local link where the user enters credentials for one data source. The credentials go "+
			"straight from the user's browser to the database's encrypted store (or the datasources file without one), "+
			"never through this conversation.",
		obj([]string{"source"}, map[string]any{"source": map[string]any{"type": "string",
			"description": "The data source name as data_sources lists it"}}),
		&mcp.ToolAnnotations{OpenWorldHint: boolPtr(false)},
		func(_ context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (*mcp.CallToolResult, error) {
			var a struct{ Source string }
			if err := json.Unmarshal(raw, &a); err != nil {
				return nil, err
			}
			if op.KeyLinks == nil {
				return nil, errors.New("this connection cannot serve key links; add the key with " +
					"'amass secrets set' or to the datasources file (config/datasources.yaml in the Compose stack)")
			}

			link, expires, err := op.KeyLinks.New(a.Source)
			if err != nil {
				return nil, err
			}

			return jsonResult(map[string]any{"url": link, "expires": expires.Format(time.RFC3339),
				"next": "Give the user this link to open in a browser on the computer running Amass. It works once."}), nil
		})
}

// dataSourceStatus lists the data sources with and without credentials,
// from the datasources file, the environment and the secrets store.
func dataSourceStatus(op *Operator) (*mcp.CallToolResult, error) {
	others, err := secrets.Sources(op.Secrets, os.Environ())
	if err != nil {
		return nil, err
	}
	if op.DataSources == "" && len(others) == 0 {
		return nil, errors.New("no datasources file is configured and no credentials are stored")
	}

	var st []collect.SourceStatus
	if op.DataSources != "" {
		if st, err = collect.DataSourceStatus(op.DataSources); err != nil {
			return nil, err
		}
	}

	from := map[string]string{}
	var with, without []string
	for _, s := range st {
		key := secrets.SourceKey(s.Name)
		switch p, ok := others[key]; {
		case s.Configured:
		case ok:
			from[s.Name] = p
		default:
			without = append(without, s.Name)
			continue
		}
		with = append(with, s.Name)
		delete(others, key)
	}
	// sources only the environment or the store has credentials for
	for key, p := range others {
		name := strings.ToLower(key)
		with = append(with, name)
		from[name] = p
	}
	sort.Strings(with)

	return jsonResult(map[string]any{"configured": with, "without_credentials": without, "credentials_from": from,
		"note": "Sources without credentials are skipped. Sources not in credentials_from use the datasources " +
			"file. Use data_source_key_link to let the user add a key."}), nil
}
