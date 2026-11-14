// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/collect"
	"github.com/owasp-amass/amass/v5/internal/graph"
	oam "github.com/owasp-amass/open-asset-model"
)

type fakeEngine struct {
	mu       sync.Mutex
	sessions map[uuid.UUID]bool
	seeded   []oam.Asset
}

func (f *fakeEngine) CreateSession(context.Context, *config.Config) (uuid.UUID, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	id := uuid.New()
	f.sessions[id] = true
	return id, nil
}

func (f *fakeEngine) CreateAsset(_ context.Context, _ uuid.UUID, a oam.Asset) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seeded = append(f.seeded, a)
	return "1", nil
}

func (f *fakeEngine) SessionStats(context.Context, uuid.UUID) (*et.SessionStats, error) {
	return &et.SessionStats{WorkItemsCompleted: 1, WorkItemsTotal: 3}, nil
}

func (f *fakeEngine) TerminateSession(_ context.Context, id uuid.UUID) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.sessions, id)
	return nil
}

func (f *fakeEngine) ListSessions(context.Context) ([]uuid.UUID, error) { return nil, nil }

func (f *fakeEngine) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.seeded)
}

const (
	readerToken   = "reader-token-0123456789-0123456789-0123"
	operatorToken = "operator-token-0123456789-0123456789-01"
)

type operatorFixture struct {
	url     string
	engine  *fakeEngine
	sources string
	op      *Operator
}

func newOperatorFixture(t *testing.T) *operatorFixture {
	t.Helper()
	dir := t.TempDir()
	sources := filepath.Join(dir, "datasources.yaml")
	if err := os.WriteFile(sources, []byte("datasources:\n#  - name: Shodan\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	f := &fakeEngine{sessions: map[uuid.UUID]bool{}}
	m := &collect.Manager{Engine: f, Config: func() (*config.Config, error) { return config.NewConfig(), nil },
		PollInterval: time.Hour}
	t.Cleanup(m.Close)
	op := &Operator{Collect: m, Journal: filepath.Join(dir, "review.jsonl"), DataSources: sources,
		KeyLinks: &KeyLinks{Path: sources}}
	svc := NewHTTPServer(ai.ToolRunner{Limits: graph.DefaultLimits()}, readerToken)
	svc.OperatorToken, svc.Operator = operatorToken, op
	// The mux is built per request so a test can add pages after start.
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		svc.Handler().ServeHTTP(w, r)
	}))
	t.Cleanup(server.Close)
	op.KeyLinks.BaseURL = server.URL
	return &operatorFixture{url: server.URL, engine: f, sources: sources, op: op}
}

type bearer struct {
	token string
	base  http.RoundTripper
}

func (b bearer) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("Authorization", "Bearer "+b.token)
	return b.base.RoundTrip(r)
}

// connect opens a session with the SDK's client, which uses the newest
// protocol: approval requests come back as input-required results.
func connect(t *testing.T, url, token string, elicit func(*mcp.ElicitRequest) (*mcp.ElicitResult, error)) *mcp.ClientSession {
	t.Helper()
	var opts *mcp.ClientOptions
	if elicit != nil {
		opts = &mcp.ClientOptions{ElicitationHandler: func(_ context.Context, r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			return elicit(r)
		}}
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, opts)
	cs, err := client.Connect(context.Background(), &mcp.StreamableClientTransport{Endpoint: url + "/mcp",
		HTTPClient: &http.Client{Transport: bearer{token, http.DefaultTransport}}, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func toolNames(t *testing.T, cs *mcp.ClientSession) map[string]bool {
	t.Helper()
	res, err := cs.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]bool{}
	for _, tool := range res.Tools {
		out[tool.Name] = true
	}
	return out
}

func call(t *testing.T, cs *mcp.ClientSession, name string, args map[string]any) (string, bool) {
	t.Helper()
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	var text strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text.WriteString(tc.Text)
		}
	}
	return text.String(), res.IsError
}

func planID(t *testing.T, cs *mcp.ClientSession, target, mode string) string {
	t.Helper()
	text, isErr := call(t, cs, ToolPlanEnumeration, map[string]any{"target": target, "mode": mode})
	if isErr {
		t.Fatalf("plan: %s", text)
	}
	var out struct{ Plan collect.Plan }
	if err := json.Unmarshal([]byte(text), &out); err != nil {
		t.Fatal(err)
	}
	return out.Plan.ID
}

func TestOperatorToolsNeedTheOperatorToken(t *testing.T) {
	fx := newOperatorFixture(t)
	reader := toolNames(t, connect(t, fx.url, readerToken, nil))
	if reader[ToolStartEnumeration] || reader[ToolReviewProposal] || !reader["walk_relations"] {
		t.Errorf("reader tools = %v", reader)
	}
	operator := toolNames(t, connect(t, fx.url, operatorToken, nil))
	for _, name := range []string{ToolPlanEnumeration, ToolStartEnumeration, ToolEnumerationStatus,
		ToolStopEnumeration, ToolListProposals, ToolReviewProposal, ToolDataSources, ToolDataSourceKey,
		"walk_relations"} {
		if !operator[name] {
			t.Errorf("operator tools lack %s", name)
		}
	}
}

// Every tool's input schema is one strict clients accept: an object whose
// required list, when present, is an array.
func TestToolSchemasAreValid(t *testing.T) {
	fx := newOperatorFixture(t)
	res, err := connect(t, fx.url, operatorToken, nil).ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range res.Tools {
		data, _ := json.Marshal(tool.InputSchema)
		var schema map[string]any
		if err := json.Unmarshal(data, &schema); err != nil || schema["type"] != "object" {
			t.Errorf("%s schema = %s", tool.Name, data)
		}
		if req, ok := schema["required"]; ok {
			if _, isArray := req.([]any); !isArray {
				t.Errorf("%s required = %v", tool.Name, req)
			}
		}
	}
}

func TestStartEnumerationAsksTheUser(t *testing.T) {
	fx := newOperatorFixture(t)
	var asked []string
	answer := "decline"
	cs := connect(t, fx.url, operatorToken, func(r *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
		asked = append(asked, r.Params.Message)
		if answer == "accept" {
			return &mcp.ElicitResult{Action: "accept", Content: map[string]any{"approve": true}}, nil
		}
		return &mcp.ElicitResult{Action: answer}, nil
	})

	id := planID(t, cs, "Example.com", "active")
	if text, isErr := call(t, cs, ToolStartEnumeration, map[string]any{"target": "example.com", "mode": "active",
		"plan_id": "wrong"}); !isErr || !strings.Contains(text, "does not match") {
		t.Errorf("a mismatched plan_id started: %s", text)
	}

	text, isErr := call(t, cs, ToolStartEnumeration, map[string]any{"target": "example.com", "mode": "active",
		"plan_id": id})
	if !isErr || !strings.Contains(text, "did not approve") || fx.engine.count() != 0 {
		t.Fatalf("a declined enumeration started: %s", text)
	}
	if len(asked) != 1 || !strings.Contains(asked[0], "ACTIVE enumeration of domain example.com") {
		t.Errorf("approval prompt = %q", asked)
	}

	answer = "accept"
	text, isErr = call(t, cs, ToolStartEnumeration, map[string]any{"target": "example.com", "mode": "active",
		"plan_id": id})
	if isErr || fx.engine.count() != 1 {
		t.Fatalf("an approved enumeration did not start: %s", text)
	}
	var started struct{ Run collect.Run }
	if err := json.Unmarshal([]byte(text), &started); err != nil || started.Run.State != collect.StateRunning ||
		!strings.Contains(started.Run.ApprovedBy, "test-client (approval dialog)") {
		t.Fatalf("run = %+v (%v)", started.Run, err)
	}

	status, _ := call(t, cs, ToolEnumerationStatus, map[string]any{})
	if !strings.Contains(status, started.Run.ID) {
		t.Errorf("status lacks the run: %s", status)
	}
	if text, isErr := call(t, cs, ToolStopEnumeration, map[string]any{"run_id": started.Run.ID}); isErr ||
		!strings.Contains(text, collect.StateStopped) {
		t.Errorf("stop: %s", text)
	}
}

// A client without an approval dialog relies on its own tool approval,
// unless the server requires the dialog.
func TestClientsWithoutApprovalDialogs(t *testing.T) {
	fx := newOperatorFixture(t)
	cs := connect(t, fx.url, operatorToken, nil)
	id := planID(t, cs, "AS64500", "")
	if text, isErr := call(t, cs, ToolStartEnumeration, map[string]any{"target": "AS64500", "plan_id": id}); isErr ||
		!strings.Contains(text, "client tool approval") {
		t.Fatalf("start without a dialog: %s", text)
	}

	fx.op.RequireConfirmation = true
	id = planID(t, cs, "8.8.8.0/24", "passive")
	if text, isErr := call(t, cs, ToolStartEnumeration, map[string]any{"target": "8.8.8.0/24", "plan_id": id}); !isErr ||
		!strings.Contains(text, "cannot show an approval dialog") {
		t.Errorf("a required dialog was skipped: %s", text)
	}
}

// A client on an older protocol version gets the approval request on the
// tool call's event stream and answers it with a separate POST.
func TestApprovalOnOlderProtocol(t *testing.T) {
	fx := newOperatorFixture(t)
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",` +
		`"capabilities":{"elicitation":{"form":{}}},"clientInfo":{"name":"old-client","version":"1"}}}`
	code, header, _ := postSSE(t, fx.url, operatorToken, "", init)
	session := header.Get("Mcp-Session-Id")
	if code != 200 || session == "" {
		t.Fatalf("initialize: %d", code)
	}
	postSSE(t, fx.url, operatorToken, session, `{"jsonrpc":"2.0","method":"notifications/initialized"}`)

	id := collect.PlanID("domain", "example.org", collect.Passive)
	body := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"start_enumeration",` +
		`"arguments":{"target":"example.org","plan_id":"` + id + `"}}}`
	req, _ := http.NewRequest("POST", fx.url+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+operatorToken)
	req.Header.Set("Mcp-Session-Id", session)
	req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	lines := bufio.NewScanner(resp.Body)
	var result string
	var seen []string
	defer func() {
		if t.Failed() {
			t.Logf("status %d, stream:\n%s", resp.StatusCode, strings.Join(seen, "\n"))
		}
	}()
	for lines.Scan() {
		seen = append(seen, lines.Text())
		data, ok := strings.CutPrefix(lines.Text(), "data: ")
		if !ok {
			continue
		}
		var msg struct {
			ID     json.RawMessage `json:"id"`
			Method string          `json:"method"`
			Result json.RawMessage `json:"result"`
			Error  json.RawMessage `json:"error"`
		}
		if json.Unmarshal([]byte(data), &msg) != nil {
			continue
		}
		if msg.Method == "elicitation/create" {
			reply := `{"jsonrpc":"2.0","id":` + string(msg.ID) +
				`,"result":{"action":"accept","content":{"approve":true}}}`
			if code, _, _ := postSSE(t, fx.url, operatorToken, session, reply); code != 202 {
				t.Fatalf("approval reply: %d", code)
			}
			continue
		}
		if string(msg.ID) == "7" {
			result = string(msg.Result) + string(msg.Error)
			break
		}
	}
	if !strings.Contains(result, collect.StateRunning) || fx.engine.count() != 1 {
		t.Fatalf("result = %s", result)
	}
}

func postSSE(t *testing.T, base, token, session, body string) (int, http.Header, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", base+"/mcp", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Authorization", "Bearer "+token)
	if session != "" {
		req.Header.Set("Mcp-Session-Id", session)
		req.Header.Set("Mcp-Protocol-Version", "2025-11-25")
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Read the whole response, as a client does: the server finishes
	// registering a session only once its initialize stream ends.
	var out strings.Builder
	data, _ := io.ReadAll(resp.Body)
	out.Write(data)
	return resp.StatusCode, resp.Header, out.String()
}

func TestSessionsBelongToTheirToken(t *testing.T) {
	fx := newOperatorFixture(t)
	init := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-11-25",` +
		`"capabilities":{},"clientInfo":{"name":"t","version":"1"}}}`
	code, header, _ := post(t, fx.url, readerToken, "", init)
	if code != 200 {
		t.Fatalf("initialize: %d", code)
	}
	if code, _, _ := post(t, fx.url, operatorToken, header.Get("Mcp-Session-Id"),
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`); code != 404 {
		t.Errorf("a reader session was used with the operator token: %d", code)
	}
}

func TestDataSourceKeyLink(t *testing.T) {
	fx := newOperatorFixture(t)
	cs := connect(t, fx.url, operatorToken, nil)
	text, isErr := call(t, cs, ToolDataSources, map[string]any{})
	if isErr || !strings.Contains(text, "Shodan") {
		t.Fatalf("data sources: %s", text)
	}

	text, isErr = call(t, cs, ToolDataSourceKey, map[string]any{"source": "Shodan"})
	if isErr {
		t.Fatal(text)
	}
	var link struct{ URL string }
	if err := json.Unmarshal([]byte(text), &link); err != nil || !strings.HasPrefix(link.URL, fx.url+keyLinkPrefix) {
		t.Fatalf("link = %s", text)
	}

	page, err := http.Get(link.URL)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if page.StatusCode != 200 || !strings.Contains(string(body), "Shodan credentials") {
		t.Fatalf("form = %d %s", page.StatusCode, body)
	}

	resp, err := http.PostForm(link.URL, url.Values{"apikey": {"sk-test-123"}, "account": {"account"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != 200 || !strings.Contains(string(body), "Saved") || strings.Contains(string(body), "sk-test") {
		t.Fatalf("post = %d %s", resp.StatusCode, body)
	}
	data, _ := os.ReadFile(fx.sources)
	if !strings.Contains(string(data), "sk-test-123") {
		t.Errorf("key not stored:\n%s", data)
	}

	// The link works once.
	resp, err = http.PostForm(link.URL, url.Values{"apikey": {"again"}})
	if err != nil {
		t.Fatal(err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != 404 {
		t.Errorf("a used link worked again: %d", resp.StatusCode)
	}

	text, _ = call(t, cs, ToolDataSources, map[string]any{})
	var st struct {
		Configured []string `json:"configured"`
	}
	if err := json.Unmarshal([]byte(text), &st); err != nil || len(st.Configured) != 1 {
		t.Errorf("after: %s", text)
	}
}

func TestReviewToolsReadTheJournal(t *testing.T) {
	fx := newOperatorFixture(t)
	cs := connect(t, fx.url, operatorToken, nil)
	if text, isErr := call(t, cs, ToolListProposals, map[string]any{}); isErr {
		t.Errorf("list proposals: %s", text)
	}
	text, isErr := call(t, cs, ToolReviewProposal, map[string]any{"proposal_id": "own-missing", "decision": "reject"})
	if !isErr || !strings.Contains(text, "own-missing") {
		t.Errorf("reject of a missing proposal: %s", text)
	}
}

func TestPlanForReadsTargets(t *testing.T) {
	cases := map[string]string{"example.com": "domain", "8.8.8.8": "ip", "8.8.8.0/24": "cidr", "AS15169": "asn",
		"15169": "asn"}
	for target, want := range cases {
		if p := planFor(target, ""); p.ScopeType != want || p.Mode != collect.Passive {
			t.Errorf("%s = %+v", target, p)
		}
	}
	if p := planFor("example.com", "loud"); p.Status != collect.StatusUnsupported {
		t.Errorf("unknown mode planned: %+v", p)
	}
}

// Without an approval dialog, an HTTP server hands the assistant a link the
// user opens to approve; nothing happens before they do.
func TestApprovalLinks(t *testing.T) {
	fx := newOperatorFixture(t)
	fx.op.Approvals = &ApprovalLinks{BaseURL: fx.url}
	cs := connect(t, fx.url, operatorToken, nil)
	start := func() string {
		id := planID(t, cs, "example.net", "passive")
		text, isErr := call(t, cs, ToolStartEnumeration, map[string]any{"target": "example.net", "plan_id": id})
		var out struct {
			Status string
			URL    string `json:"approval_url"`
		}
		if isErr || json.Unmarshal([]byte(text), &out) != nil || out.Status != "awaiting_approval" ||
			!strings.HasPrefix(out.URL, fx.url+approvalPrefix) {
			t.Fatalf("start = %s", text)
		}
		return out.URL
	}

	link := start()
	if fx.engine.count() != 0 {
		t.Fatal("an enumeration started before approval")
	}
	page, err := http.Get(link)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(page.Body)
	_ = page.Body.Close()
	if !strings.Contains(string(body), "PASSIVE enumeration of domain example.net") || fx.engine.count() != 0 {
		t.Fatalf("approval page: %s", body)
	}
	if resp, err := http.PostForm(link, url.Values{"decision": {"decline"}}); err != nil || fx.engine.count() != 0 {
		t.Fatalf("decline: %v", err)
	} else {
		_ = resp.Body.Close()
	}

	link = start()
	resp, err := http.PostForm(link, url.Values{"decision": {"approve"}})
	if err != nil {
		t.Fatal(err)
	}
	body, _ = io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if fx.engine.count() != 1 || !strings.Contains(string(body), "approval link") {
		t.Fatalf("approve: %s", body)
	}
	if resp, _ := http.PostForm(link, url.Values{"decision": {"approve"}}); resp.StatusCode != 404 || fx.engine.count() != 1 {
		t.Error("an approval link worked twice")
	}
}
