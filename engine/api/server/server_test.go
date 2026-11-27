// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package server

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// manager holds the sessions a test makes, and records the cancelled ones.
type manager struct {
	mu        sync.Mutex
	t         *testing.T
	sessions  map[uuid.UUID]et.Session
	cancelled chan uuid.UUID
}

func (m *manager) NewSession(cfg *config.Config) (et.Session, error) {
	if len(cfg.Domains()) == 0 {
		return nil, errors.New("no scope")
	}

	s := plugintest.NewSession(m.t)
	if err := m.AddSession(s); err != nil {
		return nil, err
	}
	return s, nil
}

func (m *manager) AddSession(s et.Session) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.sessions[s.ID()] = s
	return nil
}

func (m *manager) CancelSession(id uuid.UUID) { m.cancelled <- id }

func (m *manager) GetSession(id uuid.UUID) et.Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.sessions[id]
}

func (m *manager) GetSessions() []et.Session {
	m.mu.Lock()
	defer m.mu.Unlock()

	var out []et.Session
	for _, s := range m.sessions {
		out = append(out, s)
	}

	return out
}

func (m *manager) Shutdown() {}

func newServer(t *testing.T) (http.Handler, *manager, *plugintest.Dispatcher) {
	t.Helper()

	mgr := &manager{t: t, sessions: map[uuid.UUID]et.Session{}, cancelled: make(chan uuid.UUID, 1)}
	disp := &plugintest.Dispatcher{}
	srv, err := NewServer(slog.New(slog.NewTextHandler(io.Discard, nil)), disp, mgr)
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(srv.cancel)

	return srv.srv.Handler, mgr, disp
}

func do(t *testing.T, h http.Handler, method, path, body string) (int, map[string]any) {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))

	out := map[string]any{}
	if rec.Body.Len() > 0 {
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("%s %s answered %d with a body that is not JSON: %q", method, path, rec.Code, rec.Body.String())
		}
	}

	return rec.Code, out
}

func TestHealthAndUnknownRoutes(t *testing.T) {
	h, _, _ := newServer(t)

	if code, out := do(t, h, http.MethodGet, "/api/v1/health", ""); code != http.StatusOK || out["result"] == nil {
		t.Errorf("health gave %d %v", code, out)
	}
	if code, out := do(t, h, http.MethodGet, "/api/v1/nothing", ""); code != http.StatusNotFound ||
		out["code"] != float64(http.StatusNotFound) {
		t.Errorf("an unknown route gave %d %v", code, out)
	}
	if code, _ := do(t, h, http.MethodPut, "/api/v1/health", ""); code != http.StatusMethodNotAllowed {
		t.Errorf("a wrong method gave %d", code)
	}
	if code, _ := do(t, h, http.MethodGet, "/api/v1/sessions/not-a-uuid/stats", ""); code != http.StatusNotFound {
		t.Errorf("a malformed session token gave %d", code)
	}
}

// A session is created from a configuration, listed, reported on and
// terminated.
func TestSessionLifecycle(t *testing.T) {
	h, mgr, _ := newServer(t)

	// an engine with no sessions says so, so a client can tell a session is gone
	if code, out := do(t, h, http.MethodGet, "/api/v1/sessions/list", ""); code != http.StatusOK ||
		len(out["sessionTokens"].([]any)) != 0 {
		t.Errorf("listing no sessions gave %d %v", code, out)
	}
	if code, _ := do(t, h, http.MethodPost, "/api/v1/sessions", "{not json"); code != http.StatusBadRequest {
		t.Errorf("a malformed configuration gave %d", code)
	}
	if code, _ := do(t, h, http.MethodPost, "/api/v1/sessions", "[1,2]"); code != http.StatusBadRequest {
		t.Errorf("a configuration that is not an object gave %d", code)
	}
	if code, _ := do(t, h, http.MethodPost, "/api/v1/sessions", "{}"); code != http.StatusBadRequest {
		t.Errorf("a configuration without a scope gave %d", code)
	}

	code, out := do(t, h, http.MethodPost, "/api/v1/sessions", `{"scope":{"domains":["example.com"]}}`)
	token, _ := out["sessionToken"].(string)
	if code != http.StatusCreated || uuid.Validate(token) != nil {
		t.Fatalf("creating a session gave %d %v", code, out)
	}

	if code, out := do(t, h, http.MethodGet, "/api/v1/sessions/list", ""); code != http.StatusOK ||
		len(out["sessionTokens"].([]any)) != 1 {
		t.Errorf("listing gave %d %v", code, out)
	}
	if code, out := do(t, h, http.MethodGet, "/api/v1/sessions/"+token+"/stats", ""); code != http.StatusOK ||
		out["workItemsCompleted"] != float64(0) {
		t.Errorf("stats gave %d %v", code, out)
	}
	if code, _ := do(t, h, http.MethodGet, "/api/v1/sessions/"+uuid.NewString()+"/stats", ""); code !=
		http.StatusNotFound {
		t.Errorf("an unknown session's stats gave %d", code)
	}

	if code, _ := do(t, h, http.MethodDelete, "/api/v1/sessions/"+token, ""); code != http.StatusNoContent {
		t.Errorf("terminating gave %d", code)
	}
	if id := <-mgr.cancelled; id.String() != token {
		t.Errorf("session %s was cancelled, want %s", id, token)
	}
}

// Assets added one at a time or in bulk are stored once and dispatched,
// and the scope reports what the session's scope holds.
func TestAddAssetsAndScope(t *testing.T) {
	h, mgr, disp := newServer(t)

	_, out := do(t, h, http.MethodPost, "/api/v1/sessions", `{"scope":{"domains":["example.com"]}}`)
	token := out["sessionToken"].(string)
	base := "/api/v1/sessions/" + token

	code, first := do(t, h, http.MethodPost, base+"/assets/fqdn", `{"name":"www.example.com"}`)
	if code != http.StatusOK || first["entityID"] == nil {
		t.Fatalf("adding an asset gave %d %v", code, first)
	}
	if _, again := do(t, h, http.MethodPost, base+"/assets/fqdn", `{"name":"www.example.com"}`); again["entityID"] !=
		first["entityID"] {
		t.Errorf("adding the same asset again gave entity %v, want %v", again["entityID"], first["entityID"])
	}
	if code, _ := do(t, h, http.MethodPost, base+"/assets/fqdn", `"www.example.com"`); code != http.StatusBadRequest {
		t.Errorf("an asset that is not an object gave %d", code)
	}

	code, out = do(t, h, http.MethodPost, base+"/assets/fqdn:bulk",
		`{"items":[{"name":"a.example.com"},{"name":"b.example.com"},"bad"]}`)
	// the item that is not an asset is counted as failed
	if code != http.StatusOK || out["ingested"] != float64(2) || out["stored"] != float64(2) ||
		out["failed"] != float64(1) {
		t.Errorf("a bulk add gave %d %v", code, out)
	}
	if code, _ := do(t, h, http.MethodPost, base+"/assets/fqdn:bulk", `{"items":[]}`); code != http.StatusBadRequest {
		t.Errorf("an empty bulk add gave %d", code)
	}
	if n := len(disp.Events()); n != 4 {
		t.Errorf("%d events were dispatched, want 4", n)
	}

	id, _ := uuid.Parse(token)
	mgr.GetSession(id).Scope().AddDomain("example.com")
	if code, out := do(t, h, http.MethodGet, base+"/scope/fqdn", ""); code != http.StatusOK ||
		len(out["data"].([]any)) != 1 {
		t.Errorf("the FQDN scope gave %d %v", code, out)
	}
	if code, _ := do(t, h, http.MethodGet, base+"/scope/netblock", ""); code != http.StatusNotFound {
		t.Errorf("an empty scope gave %d", code)
	}
}

// A request body larger than the limit is refused rather than read into
// memory.
func TestRequestBodyLimit(t *testing.T) {
	h, _, _ := newServer(t)

	_, out := do(t, h, http.MethodPost, "/api/v1/sessions", `{"scope":{"domains":["example.com"]}}`)
	base := "/api/v1/sessions/" + out["sessionToken"].(string)

	big := `{"items":["` + strings.Repeat("x", maxRequestBody) + `"]}`
	if code, _ := do(t, h, http.MethodPost, base+"/assets/fqdn:bulk", big); code != http.StatusBadRequest {
		t.Errorf("an oversized body gave %d", code)
	}
}

// The log stream relays what the session publishes, and refuses an unknown
// session.
func TestLogStream(t *testing.T) {
	h, mgr, _ := newServer(t)
	srv := httptest.NewServer(h)
	defer srv.Close()

	_, out := do(t, h, http.MethodPost, "/api/v1/sessions", `{"scope":{"domains":["example.com"]}}`)
	token := out["sessionToken"].(string)
	id, _ := uuid.Parse(token)

	ws := "ws" + strings.TrimPrefix(srv.URL, "http") + "/api/v1/sessions/"
	if _, resp, err := websocket.DefaultDialer.Dial(ws+uuid.NewString()+"/ws/logs", nil); err == nil ||
		resp == nil || resp.StatusCode != http.StatusNotFound {
		t.Errorf("an unknown session's log stream was opened (%v)", err)
	}

	conn, _, err := websocket.DefaultDialer.Dial(ws+token+"/ws/logs", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()

	// the handler subscribes after the upgrade; publish until the line arrives
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			select {
			case <-done:
				return
			case <-time.After(50 * time.Millisecond):
				mgr.GetSession(id).PubSub().Publish("engine log line")
			}
		}
	}()
	_, msg, err := conn.ReadMessage()
	if err != nil || string(msg) != "engine log line" {
		t.Errorf("received %q, %v", msg, err)
	}
}
