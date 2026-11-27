// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/internal/confighelp"
	"github.com/owasp-amass/amass/v5/resources"
)

// Config assistant tool names.
const (
	ToolDescribeConfig = "describe_config"
	ToolValidateConfig = "validate_config"
	ToolApplyConfig    = "apply_config"
)

// configAssistCapabilities are the config assistant tools. The connected
// assistant is the model: describe_config gives it the schema, current values
// and a starter template; validate_config checks a draft it writes; and
// apply_config, operator tier, writes the draft once the user approves. The
// server runs no model of its own, so these work the same over HTTP and
// stdio. Data source credentials never pass through here: describe_config
// masks them and apply_config refuses a draft that sets any.
func configAssistCapabilities(configFile string) []capability {
	return []capability{
		describeConfigCapability(configFile),
		validateConfigCapability(configFile),
		applyConfigCapability(configFile),
	}
}

// configNote tells the assistant how the config tools fit together.
const configNote = "Draft a complete configuration (start from template for a new one), check it with " +
	"validate_config, then call apply_config with the same content; the user approves the change. Never set data " +
	"source API keys here — they are entered by the operator through data_source_key_link."

func describeConfigCapability(configFile string) capability {
	return capability{tier: tierRead,
		tool: &mcp.Tool{Name: ToolDescribeConfig, Title: "Describe the Amass configuration",
			Description: "Explain the Amass configuration schema so you can read or write one: the sections, every " +
				"field with its type, default, description and an example, the current configuration (data source " +
				"credentials masked) and a commented template to start a new file from. Pass section to narrow it.",
			InputSchema: map[string]any{"type": "object", "additionalProperties": false,
				"properties": map[string]any{"section": map[string]any{"type": "string",
					"description": "Limit the fields to one section: seed, scope, options, transformations, " +
						"datasources or ai"}}},
			Annotations: &mcp.ToolAnnotations{Title: "Describe the Amass configuration", ReadOnlyHint: true,
				IdempotentHint: true, OpenWorldHint: boolPtr(false)}},
		handle: func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct{ Section string }
			if req.Params != nil && len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &a); err != nil {
					return errorResult(err), nil
				}
			}

			cat, err := confighelp.Load()
			if err != nil {
				return errorResult(err), nil
			}

			section := strings.TrimSpace(a.Section)
			if section != "" {
				if _, ok := cat.Sections[section]; !ok {
					return errorResult(fmt.Errorf("no configuration section %q; the sections are %s",
						section, strings.Join(cat.SectionNames(), ", "))), nil
				}
			}

			fields := map[string]confighelp.Field{}
			for _, path := range cat.Paths() {
				f, _ := cat.Lookup(path)
				if section == "" || f.Section == section {
					fields[path] = f
				}
			}

			out := map[string]any{"sections": cat.Sections, "fields": fields, "note": configNote}
			if section == "" {
				if tmpl, err := resources.GetResourceFileData("config.yaml"); err == nil {
					out["template"] = string(tmpl)
				}
			}
			if configFile != "" {
				out["current_path"] = configFile
				if raw, err := os.ReadFile(configFile); err == nil {
					safe, rerr := confighelp.RedactSecrets(string(raw))
					if rerr != nil {
						// Show nothing rather than risk leaking an unparsed secret.
						out["current_error"] = "the current configuration could not be read safely"
					} else {
						out["current"] = safe
					}
				}
			}

			return jsonResult(out), nil
		}}
}

func validateConfigCapability(configFile string) capability {
	return capability{tier: tierRead,
		tool: &mcp.Tool{Name: ToolValidateConfig, Title: "Validate an Amass configuration",
			Description: "Check a complete configuration draft with the real Amass loader and show how it differs " +
				"from the current one (credentials masked), without changing anything. Use it to get a draft right " +
				"before apply_config.",
			InputSchema: map[string]any{"type": "object", "required": []string{"content"},
				"additionalProperties": false, "properties": map[string]any{"content": map[string]any{"type": "string",
					"description": "The complete configuration file to check, in YAML"}}},
			Annotations: &mcp.ToolAnnotations{Title: "Validate an Amass configuration", ReadOnlyHint: true,
				IdempotentHint: true, OpenWorldHint: boolPtr(false)}},
		handle: func(_ context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
			var a struct{ Content string }
			if req.Params != nil && len(req.Params.Arguments) > 0 {
				if err := json.Unmarshal(req.Params.Arguments, &a); err != nil {
					return errorResult(err), nil
				}
			}

			out := map[string]any{}
			edit := confighelp.ProposedEdit{Content: a.Content}
			if err := edit.Validate(); err != nil {
				out["valid"] = false
				out["error"] = err.Error()
			} else {
				out["valid"] = true
				if w := edit.Warnings(); len(w) > 0 {
					out["warnings"] = w
				}
			}
			if confighelp.ContainsSecrets(a.Content) {
				out["contains_secrets"] = true
				out["note"] = "Remove the data source credentials: apply_config will refuse them. The operator " +
					"adds keys through data_source_key_link."
			}
			if diff := configDiff(configFile, a.Content); diff != "" {
				out["diff"] = diff
			}

			return jsonResult(out), nil
		}}
}

func applyConfigCapability(configFile string) capability {
	return capability{tier: tierOperator,
		tool: &mcp.Tool{Name: ToolApplyConfig, Title: "Apply an Amass configuration",
			Description: "Write a complete configuration draft to the Amass configuration file; the user is asked to " +
				"approve the change first and sees the exact difference. Validate it with validate_config first. " +
				"Never include data source credentials.",
			InputSchema: map[string]any{"type": "object", "required": []string{"content"},
				"additionalProperties": false, "properties": map[string]any{
					"content":   map[string]any{"type": "string", "description": "The complete configuration file, in YAML"},
					"summary":   map[string]any{"type": "string", "description": "A one-line description of the change"},
					"rationale": map[string]any{"type": "string", "description": "Why the change is made and its trade-offs"}}},
			Annotations: &mcp.ToolAnnotations{Title: "Apply an Amass configuration", DestructiveHint: boolPtr(true),
				OpenWorldHint: boolPtr(false)}},
		approve: func(_ context.Context, _ *mcp.CallToolRequest, raw json.RawMessage) (string,
			func(via string) (*mcp.CallToolResult, error), error) {
			var a struct {
				Content   string
				Summary   string
				Rationale string
			}
			if err := json.Unmarshal(raw, &a); err != nil {
				return "", nil, err
			}
			if configFile == "" {
				return "", nil, errors.New("this server has no configuration file to write; set -config")
			}
			if confighelp.ContainsSecrets(a.Content) {
				return "", nil, errors.New("the configuration sets data source credentials; remove them and have " +
					"the operator add keys through data_source_key_link")
			}

			edit := confighelp.ProposedEdit{Summary: a.Summary, Rationale: a.Rationale, Content: a.Content}
			if err := edit.Validate(); err != nil {
				return "", nil, err
			}

			var b strings.Builder
			if a.Summary != "" {
				fmt.Fprintf(&b, "%s\n\n", a.Summary)
			}
			fmt.Fprintf(&b, "Write this configuration to %s?", configFile)
			if diff := configDiff(configFile, a.Content); diff != "" {
				fmt.Fprintf(&b, "\n\nChanges:\n%s", diff)
			}

			return b.String(), func(string) (*mcp.CallToolResult, error) {
				if err := edit.Apply(configFile); err != nil {
					return nil, err
				}

				return jsonResult(map[string]any{"written": configFile, "summary": a.Summary,
					"next": "The new configuration applies to the next enumeration."}), nil
			}, nil
		}}
}

// configDiff returns a readable, credential-masked difference between the
// current configuration file and a proposed one, or "" when it cannot be
// computed. Both sides are masked so no secret appears in a diff shown to the
// model or the user.
func configDiff(configFile, proposed string) string {
	var current string
	if configFile != "" {
		if raw, err := os.ReadFile(configFile); err == nil {
			current = string(raw)
		}
	}

	safeCurrent, err := confighelp.RedactSecrets(current)
	if err != nil {
		safeCurrent = ""
	}

	safeProposed, err := confighelp.RedactSecrets(proposed)
	if err != nil {
		safeProposed = proposed
	}

	return confighelp.Diff(safeCurrent, safeProposed)
}
