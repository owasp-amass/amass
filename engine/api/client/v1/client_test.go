// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/owasp-amass/amass/v5/config"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

var token = uuid.MustParse("6f3c1c62-3f1e-4c55-9d38-0b4f6c0f8a11")

// fakeServer answers the engine API's v1 routes the way the server does.
func fakeServer(t *testing.T) *httptest.Server {
	t.Helper()
	base := "/api/v1/sessions/" + token.String()
	mux := http.NewServeMux()
	reply := func(w http.ResponseWriter, status int, body string) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}

	mux.HandleFunc("GET /api/v1/health", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"status":"ok"}`)
	})
	mux.HandleFunc("POST /api/v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		var cfg map[string]any
		if r.Header.Get("Content-Type") != "application/json" || json.NewDecoder(r.Body).Decode(&cfg) != nil {
			reply(w, http.StatusBadRequest, `{"error":"bad config"}`)
			return
		}
		reply(w, http.StatusCreated, `{"sessionToken":"`+token.String()+`","jobId":"job-1","joined":true}`)
	})
	mux.HandleFunc("GET /api/v1/sessions/list", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"sessionTokens":["`+token.String()+`"]}`)
	})
	mux.HandleFunc("DELETE "+base, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("GET "+base+"/stats", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"workItemsCompleted":3,"workItemsTotal":5}`)
	})
	mux.HandleFunc("GET "+base+"/scope/fqdn", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusOK, `{"data":[{"name":"example.com"},{"name":"example.org"}]}`)
	})
	mux.HandleFunc("GET "+base+"/scope/netblock", func(w http.ResponseWriter, _ *http.Request) {
		reply(w, http.StatusInternalServerError, `{"error":"scope unavailable","code":500}`)
	})
	mux.HandleFunc("POST "+base+"/assets/fqdn", func(w http.ResponseWriter, r *http.Request) {
		var f oamdns.FQDN
		if json.NewDecoder(r.Body).Decode(&f) != nil || f.Name != "www.example.com" {
			reply(w, http.StatusBadRequest, `{"error":"bad asset"}`)
			return
		}
		reply(w, http.StatusOK, `{"entityID":"42"}`)
	})
	mux.HandleFunc("POST "+base+"/assets/fqdn:bulk", func(w http.ResponseWriter, r *http.Request) {
		var req BulkAddAssetsRequest
		if json.NewDecoder(r.Body).Decode(&req) != nil {
			reply(w, http.StatusBadRequest, `{"error":"bad items"}`)
			return
		}
		reply(w, http.StatusOK, `{"ingested":`+itoa(len(req.Items))+`,"stored":`+itoa(len(req.Items))+`,"failed":0}`)
	})
	upgrader := websocket.Upgrader{}
	mux.HandleFunc("GET "+base+"/ws/logs", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		for _, m := range []string{"first log line", "second log line"} {
			_ = conn.WriteMessage(websocket.TextMessage, []byte(m))
		}
		_, _, _ = conn.ReadMessage() // wait for the client to leave
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func itoa(n int) string { b, _ := json.Marshal(n); return string(b) }

func newTestClient(t *testing.T) *Client {
	t.Helper()
	c, err := NewClient(fakeServer(t).URL)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestSessionCalls(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := newTestClient(t)

	if !c.HealthCheck(ctx) {
		t.Error("the health check failed")
	}
	if got, err := c.CreateSession(ctx, config.NewConfig()); err != nil || got != token {
		t.Errorf("CreateSession = %v, %v", got, err)
	}
	if got, err := c.NewSession(ctx, config.NewConfig()); err != nil || got.JobID != "job-1" || !got.Joined {
		t.Errorf("NewSession = %+v, %v", got, err)
	}
	if got, err := c.ListSessions(ctx); err != nil || len(got) != 1 || got[0] != token {
		t.Errorf("ListSessions = %v, %v", got, err)
	}
	if st, err := c.SessionStats(ctx, token); err != nil || st.WorkItemsCompleted != 3 || st.WorkItemsTotal != 5 {
		t.Errorf("SessionStats = %+v, %v", st, err)
	}
	if err := c.TerminateSession(ctx, token); err != nil {
		t.Errorf("TerminateSession: %v", err)
	}
	if err := c.TerminateSession(ctx, uuid.New()); err == nil {
		t.Error("terminating an unknown session succeeded")
	}
}

func TestScopeAndAssets(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := newTestClient(t)

	scope, err := c.SessionScope(ctx, token, oam.FQDN)
	if err != nil || len(scope) != 2 || scope[1].Key() != "example.org" {
		t.Errorf("SessionScope = %v, %v", scope, err)
	}
	if _, err := c.SessionScope(ctx, token, oam.Netblock); err == nil ||
		!strings.Contains(err.Error(), "scope unavailable") {
		t.Errorf("a server error was not reported with its message: %v", err)
	}

	if id, err := c.CreateAsset(ctx, token, &oamdns.FQDN{Name: "www.example.com"}); err != nil || id != "42" {
		t.Errorf("CreateAsset = %q, %v", id, err)
	}
	if _, err := c.CreateAsset(ctx, token, &oamdns.FQDN{Name: "other.example.com"}); err == nil ||
		!strings.Contains(err.Error(), "bad asset") {
		t.Errorf("a rejected asset was not reported: %v", err)
	}

	fqdns := []oam.Asset{&oamdns.FQDN{Name: "a.example.com"}, &oamdns.FQDN{Name: "b.example.com"}}
	if n, err := c.CreateAssetsBulk(ctx, token, "FQDN", fqdns); err != nil || n != 2 {
		t.Errorf("CreateAssetsBulk = %d, %v", n, err)
	}
	if _, err := c.CreateAssetsBulk(ctx, token, " ", fqdns); err == nil {
		t.Error("a bulk add without a type was sent")
	}
	mixed := append(fqdns, &oamnet.AutonomousSystem{Number: 64496})
	if _, err := c.CreateAssetsBulk(ctx, token, "fqdn", mixed); err == nil {
		t.Error("a bulk add of mixed types was sent")
	}
	if _, err := c.CreateAssetsBulk(ctx, token, "fqdn", make([]oam.Asset, MaxBulkItems+1)); err == nil {
		t.Error("a bulk add over the limit was sent")
	}
}

func TestSubscribe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	c := newTestClient(t)

	ch, err := c.Subscribe(ctx, token)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"first log line", "second log line"} {
		select {
		case got := <-ch:
			if got != want {
				t.Errorf("received %q, want %q", got, want)
			}
		case <-ctx.Done():
			t.Fatalf("no message; want %q", want)
		}
	}
}

func TestReadJSONError(t *testing.T) {
	if msg, err := readJSONError(`{"error":"boom","code":500}`); err != nil || msg != "boom" {
		t.Errorf("readJSONError = %q, %v", msg, err)
	}
	if _, err := readJSONError("<html>"); err == nil {
		t.Error("a non-JSON body was read as an error message")
	}
}
