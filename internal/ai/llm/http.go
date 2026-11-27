// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Throttling: a provider that is rate limiting (HTTP 429) or overloaded
// (Anthropic's 529, or 503 with a Retry-After) is asked again after the wait
// it gives in Retry-After, or after a doubling backoff when it gives none.
// Each wait is capped, and the request's context bounds them all.
var (
	throttleRetries = 4
	throttleBackoff = 2 * time.Second
	throttleMaxWait = 90 * time.Second
)

// maxReplyBytes bounds a provider's reply read into memory.
const maxReplyBytes = 4 << 20

// postJSON sends payload to url as JSON with headers, waiting out a provider
// that is throttling, and returns the final reply's status and body. client
// nil uses one with timeout.
func postJSON(ctx context.Context, client *http.Client, timeout time.Duration, url string,
	headers map[string]string, payload any) (int, []byte, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, nil, err
	}
	if client == nil {
		client = &http.Client{Timeout: timeout}
	}

	for attempt := 0; ; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
		if err != nil {
			return 0, nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		for k, v := range headers {
			req.Header.Set(k, v)
		}

		resp, err := client.Do(req)
		if err != nil {
			return 0, nil, err
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, maxReplyBytes))
		_ = resp.Body.Close()
		if err != nil {
			return 0, nil, err
		}

		wait, throttled := throttleWait(resp, attempt)
		if !throttled || attempt >= throttleRetries {
			return resp.StatusCode, body, nil
		}
		select {
		case <-ctx.Done():
			return resp.StatusCode, body, nil
		case <-time.After(wait):
		}
	}
}

// throttleWait reports whether a reply asks the client to slow down, and how
// long to wait before the next attempt.
func throttleWait(resp *http.Response, attempt int) (time.Duration, bool) {
	after, given := retryAfter(resp.Header.Get("Retry-After"))
	switch {
	case resp.StatusCode == http.StatusTooManyRequests, resp.StatusCode == 529:
	case resp.StatusCode == http.StatusServiceUnavailable && given:
	default:
		return 0, false
	}

	wait := throttleBackoff << attempt
	if given {
		wait = after
	}
	return min(max(wait, 0), throttleMaxWait), true
}

// retryAfter reads a Retry-After header: delay seconds or an HTTP date.
func retryAfter(v string) (time.Duration, bool) {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0, false
	}
	if s, err := strconv.Atoi(v); err == nil && s >= 0 {
		return time.Duration(s) * time.Second, true
	}
	if t, err := http.ParseTime(v); err == nil {
		return time.Until(t), true
	}
	return 0, false
}

// apiError returns the reason a provider gave for refusing a request, bounded
// in length: the message of {"error": {"type", "message"}} (Anthropic and
// OpenAI-compatible APIs), {"error": "..."} (Ollama), or {"detail"} and
// {"message"} (other compatible servers); otherwise the body's text.
func apiError(body []byte) string {
	var e struct {
		Error   json.RawMessage `json:"error"`
		Detail  any             `json:"detail"`
		Message string          `json:"message"`
	}
	msg := strings.TrimSpace(string(body))
	if json.Unmarshal(body, &e) == nil {
		var obj struct {
			Type    string `json:"type"`
			Message string `json:"message"`
		}
		var text string
		switch {
		case json.Unmarshal(e.Error, &obj) == nil && (obj.Type != "" || obj.Message != ""):
			msg = strings.TrimPrefix(obj.Type+": "+obj.Message, ": ")
			msg = strings.TrimSuffix(msg, ": ")
		case json.Unmarshal(e.Error, &text) == nil && text != "":
			msg = text
		case e.Detail != nil:
			if d, err := json.Marshal(e.Detail); err == nil {
				msg = strings.Trim(string(d), `"`)
			}
		case e.Message != "":
			msg = e.Message
		}
	}
	if len(msg) > 300 {
		msg = msg[:300] + "..."
	}
	return msg
}

// Refused remembers the request fields a model refused, so later requests
// leave them out rather than being refused again. Copies of a model share it
// through the pointer; a nil *Refused remembers nothing.
type Refused struct {
	fields sync.Map
}

// Has reports whether the model refused field.
func (r *Refused) Has(field string) bool {
	if r == nil {
		return false
	}
	_, ok := r.fields.Load(field)
	return ok
}

func (r *Refused) add(field string) {
	if r != nil {
		r.fields.Store(field, true)
	}
}

// refusedField returns the first of fields that a refused request's reason
// names (a 400 or 422 reply such as "`temperature` is deprecated for this
// model"), so the request can be sent once more without it; or "".
func refusedField(status int, reason string, fields ...string) string {
	if status != http.StatusBadRequest && status != http.StatusUnprocessableEntity {
		return ""
	}
	lower := strings.ToLower(reason)
	for _, f := range fields {
		if strings.Contains(lower, f) {
			return f
		}
	}
	return ""
}
