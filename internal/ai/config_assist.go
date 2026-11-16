// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai/llm"
	"github.com/owasp-amass/amass/v5/internal/confighelp"
	"github.com/owasp-amass/amass/v5/resources"
)

// SuggestConfig asks the model for a complete Amass configuration that meets
// request, grounded in the configuration schema and the current file. It
// returns a proposal validated by the real Amass loader. It never asks for or
// returns data source credentials: those are entered by the operator, and a
// proposal that sets any is refused.
func SuggestConfig(ctx context.Context, model llm.Model, current, request string) (confighelp.ProposedEdit, error) {
	if model == nil {
		return confighelp.ProposedEdit{}, errors.New("a model is required to suggest a configuration")
	}

	request = strings.TrimSpace(request)
	if request == "" {
		return confighelp.ProposedEdit{}, errors.New("a request describing the wanted configuration is required")
	}

	cat, err := confighelp.Load()
	if err != nil {
		return confighelp.ProposedEdit{}, err
	}

	catJSON, err := json.Marshal(cat)
	if err != nil {
		return confighelp.ProposedEdit{}, err
	}

	safeCurrent, err := confighelp.RedactSecrets(current)
	if err != nil {
		safeCurrent = ""
	}

	template, _ := resources.GetResourceFileData("config.yaml")

	system := `You are an Amass configuration expert. Write a COMPLETE Amass configuration file, in YAML, that meets ` +
		`the user's request. Ground every setting in the provided schema (the catalog): use only fields it describes, ` +
		`with values of the described types. The seed defines where enumeration begins; the scope bounds it and may ` +
		`expand unless it is rigid. Prefer passive settings unless the request asks otherwise. Never set data source ` +
		`credentials (no datasources creds, apikey, password or secret): those are entered by the operator, never by ` +
		`a model. Return ONLY a JSON object with summary (one line), rationale (why, and any trade-offs) and content ` +
		`(the complete YAML file).`

	user := fmt.Sprintf("Request:\n%s\n\nSchema (catalog):\n%s\n\nCurrent configuration "+
		"(credentials masked; empty if none):\n%s\n\nStarter template for reference:\n%s",
		request, string(catJSON), safeCurrent, string(template))

	resp, err := generateJSON(ctx, model,
		[]llm.Message{{Role: "system", Text: system}, {Role: "user", Text: user}}, suggestConfigSchema())
	if err != nil {
		return confighelp.ProposedEdit{}, err
	}

	var out struct {
		Summary   string `json:"summary"`
		Rationale string `json:"rationale"`
		Content   string `json:"content"`
	}
	if err := json.Unmarshal([]byte(llm.ModelJSON(resp.Text)), &out); err != nil {
		return confighelp.ProposedEdit{}, fmt.Errorf("the model did not return a usable configuration: %w", err)
	}
	if strings.TrimSpace(out.Content) == "" {
		return confighelp.ProposedEdit{}, errors.New("the model returned an empty configuration")
	}
	if confighelp.ContainsSecrets(out.Content) {
		return confighelp.ProposedEdit{}, errors.New("the model put data source credentials in the configuration; " +
			"those are entered by the operator through a one-time local link, never written by a model")
	}

	edit := confighelp.ProposedEdit{Summary: out.Summary, Rationale: out.Rationale, Content: out.Content}
	if err := edit.Validate(); err != nil {
		return confighelp.ProposedEdit{}, err
	}

	return edit, nil
}

// suggestConfigSchema constrains the model's reply to a configuration
// proposal.
func suggestConfigSchema() llm.JSONSchema {
	return llm.JSONSchema{
		Name:        "amass_configuration",
		Description: "A complete Amass configuration proposal.",
		Schema: map[string]any{
			"type":                 "object",
			"required":             []string{"summary", "content"},
			"additionalProperties": false,
			"properties": map[string]any{
				"summary":   map[string]any{"type": "string", "description": "A one-line description of the configuration"},
				"rationale": map[string]any{"type": "string", "description": "Why these settings, and any trade-offs"},
				"content":   map[string]any{"type": "string", "description": "The complete configuration file, in YAML"},
			},
		},
	}
}
