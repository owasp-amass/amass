// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// callReq builds a tool-call request carrying args as its arguments.
func callReq(t *testing.T, args any) *mcp.CallToolRequest {
	t.Helper()
	raw, err := json.Marshal(args)
	if err != nil {
		t.Fatal(err)
	}

	return &mcp.CallToolRequest{Params: &mcp.CallToolParamsRaw{Arguments: raw}}
}

const secretConfig = `scope:
  domains:
    - owasp.org
datasources:
  - name: Shodan
    creds:
      account:
        apikey: SECRET-KEY-123
`

func TestDescribeConfigMasksAndDescribes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(secretConfig), 0o600); err != nil {
		t.Fatal(err)
	}

	res, err := describeConfigCapability(path).handle(context.Background(), callReq(t, map[string]any{}))
	if err != nil || res.IsError {
		t.Fatalf("describe_config failed: %v %s", err, resultText(res))
	}

	var out struct {
		Sections map[string]string          `json:"sections"`
		Fields   map[string]json.RawMessage `json:"fields"`
		Template string                     `json:"template"`
		Current  string                     `json:"current"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sections) == 0 || len(out.Fields) == 0 {
		t.Errorf("describe_config returned no schema: %s", resultText(res))
	}
	if out.Template == "" {
		t.Error("describe_config returned no starter template")
	}
	if strings.Contains(out.Current, "SECRET-KEY-123") {
		t.Errorf("describe_config leaked a credential:\n%s", out.Current)
	}
	if !strings.Contains(out.Current, "owasp.org") {
		t.Errorf("describe_config dropped the current scope:\n%s", out.Current)
	}
}

func TestDescribeConfigSection(t *testing.T) {
	res, err := describeConfigCapability("").handle(context.Background(),
		callReq(t, map[string]any{"section": "scope"}))
	if err != nil || res.IsError {
		t.Fatalf("describe_config scope failed: %v %s", err, resultText(res))
	}

	var out struct {
		Fields map[string]struct {
			Section string `json:"section"`
		} `json:"fields"`
		Template string `json:"template"`
	}
	if err := json.Unmarshal([]byte(resultText(res)), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Fields) == 0 {
		t.Error("section scope returned no fields")
	}
	for path, f := range out.Fields {
		if f.Section != "scope" {
			t.Errorf("section scope returned a field from %q: %s", f.Section, path)
		}
	}
	if out.Template != "" {
		t.Error("a single section should not carry the whole-file template")
	}

	// An unknown section is a readable error, not a crash.
	bad, _ := describeConfigCapability("").handle(context.Background(),
		callReq(t, map[string]any{"section": "nonsense"}))
	if !bad.IsError {
		t.Error("an unknown section was accepted")
	}
}

func TestValidateConfig(t *testing.T) {
	vc := validateConfigCapability("")

	ok, _ := vc.handle(context.Background(), callReq(t, map[string]any{
		"content": "seed:\n  domains:\n    - owasp.org\n"}))
	if got := resultText(ok); !strings.Contains(got, `"valid": true`) {
		t.Errorf("a valid config was not accepted: %s", got)
	}

	bad, _ := vc.handle(context.Background(), callReq(t, map[string]any{"content": "scope: [bad\n"}))
	if got := resultText(bad); !strings.Contains(got, `"valid": false`) || !strings.Contains(got, "error") {
		t.Errorf("malformed YAML was not reported: %s", got)
	}

	sec, _ := vc.handle(context.Background(), callReq(t, map[string]any{"content": secretConfig}))
	if got := resultText(sec); !strings.Contains(got, `"contains_secrets": true`) {
		t.Errorf("credentials were not flagged: %s", got)
	}
}

func TestApplyConfigWritesAfterApproval(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	content := "seed:\n  domains:\n    - example.com\nscope:\n  ports:\n    - 443\n"

	msg, act, err := applyConfigCapability(path).approve(context.Background(), nil,
		mustJSON(t, map[string]any{"content": content, "summary": "add example.com"}))
	if err != nil {
		t.Fatalf("apply_config refused a valid change: %v", err)
	}
	if !strings.Contains(msg, "example.com") || !strings.Contains(msg, path) {
		t.Errorf("the approval message is missing the change or path: %s", msg)
	}

	res, err := act("test")
	if err != nil {
		t.Fatalf("apply failed: %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != content {
		t.Errorf("the config was not written as proposed: %q", string(got))
	}
	if !strings.Contains(resultText(res), path) {
		t.Errorf("apply result did not name the file: %s", resultText(res))
	}
}

func TestApplyConfigGuards(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")

	// Credentials are refused outright.
	if _, _, err := applyConfigCapability(path).approve(context.Background(), nil,
		mustJSON(t, map[string]any{"content": secretConfig})); err == nil {
		t.Error("apply_config accepted data source credentials")
	}

	// An invalid draft never reaches the gate.
	if _, _, err := applyConfigCapability(path).approve(context.Background(), nil,
		mustJSON(t, map[string]any{"content": "scope: [bad\n"})); err == nil {
		t.Error("apply_config accepted a malformed draft")
	}

	// Without a configured file there is nothing to write.
	if _, _, err := applyConfigCapability("").approve(context.Background(), nil,
		mustJSON(t, map[string]any{"content": "seed:\n  domains:\n    - owasp.org\n"})); err == nil {
		t.Error("apply_config wrote without a configured file")
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}

	return raw
}
