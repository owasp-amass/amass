// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package pacer

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clock is a fake time source; sleeping advances it.
type clock struct {
	mu    sync.Mutex
	t     time.Time
	slept []time.Duration
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) sleep(_ context.Context, d time.Duration) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.slept = append(c.slept, d)
	c.t = c.t.Add(d)
	return nil
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func (c *clock) waits() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.slept...)
}

func newPacer() (*Pacer, *clock) {
	c := &clock{t: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)}
	p := New()
	p.now, p.sleep = c.now, c.sleep
	return p, c
}

// server answers with the statuses in order, then 200.
func server(t *testing.T, statuses []int, header http.Header) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(hits.Add(1)) - 1
		for k, v := range header {
			w.Header()[k] = v
		}
		if n < len(statuses) {
			w.WriteHeader(statuses[n])
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func get(t *testing.T, c *http.Client, url string) (int, error) {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		return 0, err
	}
	_ = resp.Body.Close()
	return resp.StatusCode, nil
}

// A healthy source is not slowed at all.
func TestAnswersAreNotPaced(t *testing.T) {
	p, c := newPacer()
	srv, _ := server(t, nil, nil)
	client := &http.Client{Transport: p.Transport(nil)}

	for range 5 {
		if code, err := get(t, client, srv.URL); err != nil || code != 200 {
			t.Fatalf("%d %v", code, err)
		}
	}
	if w := c.waits(); len(w) != 0 {
		t.Errorf("a healthy source was paced: %v", w)
	}
}

// Refusals space requests out, doubling; answers bring the pace back.
func TestRefusalsSlowAndAnswersRecover(t *testing.T) {
	p, c := newPacer()
	srv, _ := server(t, []int{503, 503, 503}, nil)
	client := &http.Client{Transport: p.Transport(nil)}

	for range 4 {
		_, _ = get(t, client, srv.URL)
	}
	w := c.waits()
	if len(w) != 3 || w[0] != time.Second || w[1] != 2*time.Second || w[2] != 4*time.Second {
		t.Fatalf("waits %v, want 1s 2s 4s", w)
	}

	host := strings.TrimPrefix(srv.URL, "http://")
	host = host[:strings.LastIndexByte(host, ':')]
	s := p.host(host)
	for range 20 {
		_, _ = get(t, client, srv.URL)
	}
	s.mu.Lock()
	spacing := s.spacing
	s.mu.Unlock()
	if spacing != 0 {
		t.Errorf("spacing %v after many answers, want none", spacing)
	}
}

// Retry-After is honored.
func TestRetryAfter(t *testing.T) {
	p, c := newPacer()
	srv, _ := server(t, []int{429}, http.Header{"Retry-After": {"30"}})
	client := &http.Client{Transport: p.Transport(nil)}

	_, _ = get(t, client, srv.URL)
	_, _ = get(t, client, srv.URL)
	if w := c.waits(); len(w) != 1 || w[0] != 30*time.Second {
		t.Errorf("waits %v, want the 30s Retry-After", w)
	}
}

// After repeated refusals the breaker opens: requests fail at once without
// reaching the host until the cooldown ends, then one trial decides.
func TestBreakerOpensAndRecovers(t *testing.T) {
	p, c := newPacer()
	srv, hits := server(t, []int{503, 503, 503, 503, 503}, nil)
	client := &http.Client{Transport: p.Transport(nil)}

	for range openAfter {
		_, _ = get(t, client, srv.URL)
	}
	before := hits.Load()
	if _, err := get(t, client, srv.URL); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("err %v, want ErrUnavailable", err)
	}
	if hits.Load() != before {
		t.Error("a request reached a host whose breaker is open")
	}

	c.advance(cooldown + time.Second)
	if code, err := get(t, client, srv.URL); err != nil || code != 200 {
		t.Fatalf("trial after cooldown: %d %v", code, err)
	}
	if code, err := get(t, client, srv.URL); err != nil || code != 200 {
		t.Errorf("after a good trial: %d %v", code, err)
	}
}

// A failed trial reopens the breaker for twice as long.
func TestFailedTrialReopensLonger(t *testing.T) {
	p, c := newPacer()
	srv, _ := server(t, []int{503, 503, 503, 503, 503, 503}, nil)
	client := &http.Client{Transport: p.Transport(nil)}

	for range openAfter {
		_, _ = get(t, client, srv.URL)
	}
	c.advance(cooldown + time.Second)
	_, _ = get(t, client, srv.URL) // the trial, refused

	c.advance(cooldown + time.Second)
	if _, err := get(t, client, srv.URL); !errors.Is(err, ErrUnavailable) {
		t.Errorf("err %v, want still open after one cooldown", err)
	}
	c.advance(cooldown)
	if _, err := get(t, client, srv.URL); errors.Is(err, ErrUnavailable) {
		t.Error("still open after the doubled cooldown")
	}
}

// Ordinary answers, a 404 or a 500, do not count as refusals.
func TestOrdinaryErrorsAreAnswers(t *testing.T) {
	if refused(&http.Response{StatusCode: 404}, nil) || refused(&http.Response{StatusCode: 500}, nil) {
		t.Error("an answer was read as a refusal")
	}
	for _, code := range []int{429, 502, 503, 504} {
		if !refused(&http.Response{StatusCode: code}, nil) {
			t.Errorf("%d was not read as a refusal", code)
		}
	}
	if !refused(nil, context.DeadlineExceeded) {
		t.Error("a timeout was not read as a refusal")
	}
}

// Each host is paced on its own.
func TestHostsArePacedApart(t *testing.T) {
	p, c := newPacer()
	bad, _ := server(t, []int{503, 503}, nil)
	client := &http.Client{Transport: p.Transport(nil)}
	_, _ = get(t, client, bad.URL)

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	t.Cleanup(good.Close)
	// httptest servers share 127.0.0.1; use a distinct host name for the good one
	req, _ := http.NewRequest(http.MethodGet, strings.Replace(good.URL, "127.0.0.1", "localhost", 1), nil)
	resp, err := client.Do(req)
	if err == nil {
		_ = resp.Body.Close()
	}
	if w := c.waits(); len(w) != 0 {
		t.Errorf("another host was paced for the refusing one: %v", w)
	}
}

// The wait hook sees each imposed wait with the request's context.
func TestOnWait(t *testing.T) {
	p, _ := newPacer()
	var got []time.Duration
	p.OnWait(func(_ context.Context, _ string, d time.Duration) { got = append(got, d) })
	srv, _ := server(t, []int{503}, nil)
	client := &http.Client{Transport: p.Transport(nil)}
	_, _ = get(t, client, srv.URL)
	_, _ = get(t, client, srv.URL)
	if len(got) != 1 || got[0] != time.Second {
		t.Errorf("hook saw %v", got)
	}
}

func TestRetryAfterDate(t *testing.T) {
	now := time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC)
	resp := &http.Response{Header: http.Header{"Retry-After": {now.Add(90 * time.Second).Format(http.TimeFormat)}}}
	if d := retryAfter(resp, now); d != 90*time.Second {
		t.Errorf("date Retry-After = %v", d)
	}
	resp.Header.Set("Retry-After", "86400")
	if d := retryAfter(resp, now); d != maxRetryAfter {
		t.Errorf("capped Retry-After = %v", d)
	}
}
