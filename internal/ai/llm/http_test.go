// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// A provider that is rate limiting is asked again after the wait it gives.
func TestPostJSONWaitsOutThrottling(t *testing.T) {
	defer func(b time.Duration) { throttleBackoff = b }(throttleBackoff)
	throttleBackoff = time.Millisecond

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		switch calls {
		case 1:
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
		case 2:
			w.WriteHeader(529) // Anthropic: overloaded, no Retry-After
		default:
			_, _ = w.Write([]byte(`{}`))
		}
	}))
	defer server.Close()

	status, _, err := postJSON(context.Background(), nil, time.Second, server.URL, nil, map[string]any{})
	if err != nil || status != http.StatusOK || calls != 3 {
		t.Fatalf("status %d, calls %d, err %v; want 200 after 3 calls", status, calls, err)
	}
}

// Throttling is retried a bounded number of times, then reported.
func TestPostJSONGivesUpOnThrottling(t *testing.T) {
	defer func(b time.Duration) { throttleBackoff = b }(throttleBackoff)
	throttleBackoff = time.Millisecond

	calls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"type":"rate_limit_error","message":"slow down"}}`))
	}))
	defer server.Close()

	status, body, err := postJSON(context.Background(), nil, time.Second, server.URL, nil, map[string]any{})
	if err != nil || status != http.StatusTooManyRequests || calls != throttleRetries+1 {
		t.Fatalf("status %d, calls %d, err %v", status, calls, err)
	}
	if got := apiError(body); got != "rate_limit_error: slow down" {
		t.Errorf("reason = %q", got)
	}
}

// A 503 is throttling only when the server says when to come back.
func TestThrottleWait(t *testing.T) {
	for _, c := range []struct {
		status    int
		after     string
		throttled bool
	}{
		{http.StatusTooManyRequests, "", true},
		{529, "", true},
		{http.StatusServiceUnavailable, "3", true},
		{http.StatusServiceUnavailable, "", false},
		{http.StatusBadRequest, "3", false},
	} {
		resp := &http.Response{StatusCode: c.status, Header: http.Header{}}
		if c.after != "" {
			resp.Header.Set("Retry-After", c.after)
		}
		if _, got := throttleWait(resp, 0); got != c.throttled {
			t.Errorf("status %d Retry-After %q: throttled %v, want %v", c.status, c.after, got, c.throttled)
		}
	}
	resp := &http.Response{StatusCode: http.StatusTooManyRequests, Header: http.Header{"Retry-After": {"600"}}}
	if wait, _ := throttleWait(resp, 0); wait != throttleMaxWait {
		t.Errorf("wait = %v, want the cap %v", wait, throttleMaxWait)
	}
}

func TestAPIError(t *testing.T) {
	for body, want := range map[string]string{
		`{"type":"error","error":{"type":"authentication_error","message":"invalid x-api-key"}}`: "authentication_error: invalid x-api-key",
		`{"error":{"message":"Incorrect API key provided"}}`:                                     "Incorrect API key provided",
		`{"error":"model \"nope\" not found"}`:                                                   `model "nope" not found`,
		`{"detail":"Not Found"}`:                                                                 "Not Found",
		`{"message":"bad request"}`:                                                              "bad request",
		`upstream unavailable`:                                                                   "upstream unavailable",
	} {
		if got := apiError([]byte(body)); got != want {
			t.Errorf("apiError(%s) = %q, want %q", body, got, want)
		}
	}
}

func TestRefusedField(t *testing.T) {
	if got := refusedField(http.StatusBadRequest, "`temperature` is deprecated for this model", "temperature"); got !=
		"temperature" {
		t.Errorf("got %q", got)
	}
	if got := refusedField(http.StatusUnauthorized, "temperature", "temperature"); got != "" {
		t.Errorf("an authentication failure is not a refused field: %q", got)
	}
	var r *Refused
	if r.Has("think") {
		t.Error("a nil Refused remembers nothing")
	}
}
