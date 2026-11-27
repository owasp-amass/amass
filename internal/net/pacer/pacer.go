// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package pacer paces HTTP requests to each data source host adaptively. A
// host that refuses for load (429, 502, 503, 504) or times out is asked less
// often, honoring its Retry-After; each answer it gives restores the pace a
// step; and a host that keeps refusing is left alone for a cooldown, after
// which one trial request decides whether it is back (a circuit breaker).
// The state is shared by every session in the process, since a provider that
// is overloaded is overloaded for all of them.
//
// Transport wraps the round tripper of a client that queries data sources.
// Active probes of a target are paced elsewhere (the probe pacer) and must
// not be wrapped: a target's 503 is evidence about the target, not a reason
// to pace a data source.
package pacer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// The pacing and breaker settings.
const (
	// firstStep is the spacing after the first refusal; each further refusal
	// doubles it up to maxSpacing.
	firstStep  = time.Second
	maxSpacing = 2 * time.Minute
	// maxRetryAfter caps a host's Retry-After.
	maxRetryAfter = 15 * time.Minute
	// recovery is the share of the spacing an answer keeps; below minSpacing
	// the spacing is dropped.
	recovery   = 0.75
	minSpacing = 50 * time.Millisecond
	// openAfter consecutive refusals open the breaker for cooldown, doubled
	// at each reopening up to maxCooldown.
	openAfter   = 5
	cooldown    = 10 * time.Minute
	maxCooldown = time.Hour
)

// ErrUnavailable is returned, without a request being sent, for a host whose
// breaker is open.
var ErrUnavailable = errors.New("pacer: the source is refusing requests; not asking again until its cooldown ends")

// state is one host's pacing.
type state struct {
	mu        sync.Mutex
	spacing   time.Duration
	next      time.Time // no request before this
	failures  int       // consecutive refusals
	openUntil time.Time // breaker open until this
	cooldown  time.Duration
	trial     bool // a half-open trial request is in flight
}

// Pacer holds every host's state.
type Pacer struct {
	mu     sync.Mutex
	hosts  map[string]*state
	now    func() time.Time
	sleep  func(context.Context, time.Duration) error
	log    *slog.Logger
	onWait func(ctx context.Context, host string, d time.Duration)
}

// New returns an empty Pacer.
func New() *Pacer {
	return &Pacer{hosts: map[string]*state{}, now: time.Now, sleep: sleepCtx}
}

// Default is the process-wide Pacer the session clients share.
var Default = New()

// SetLogger sets where state changes are logged; nil leaves them unlogged.
func (p *Pacer) SetLogger(l *slog.Logger) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.log = l
}

// OnWait sets a hook called after each wait the pacer imposes, with the
// request's context, so a session can count its waits.
func (p *Pacer) OnWait(f func(ctx context.Context, host string, d time.Duration)) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.onWait = f
}

func (p *Pacer) host(name string) *state {
	p.mu.Lock()
	defer p.mu.Unlock()
	s, ok := p.hosts[name]
	if !ok {
		s = &state{cooldown: cooldown}
		p.hosts[name] = s
	}
	return s
}

func (p *Pacer) logger() *slog.Logger {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.log
}

// Transport returns base wrapped by p.
func (p *Pacer) Transport(base http.RoundTripper) http.RoundTripper {
	if base == nil {
		base = http.DefaultTransport
	}
	return &transport{p: p, base: base}
}

type transport struct {
	p    *Pacer
	base http.RoundTripper
}

func (t *transport) RoundTrip(req *http.Request) (*http.Response, error) {
	host := strings.ToLower(req.URL.Hostname())
	if host == "" {
		return t.base.RoundTrip(req)
	}

	s := t.p.host(host)
	wait, err := t.p.admit(host, s)
	if err != nil {
		return nil, err
	}
	if wait > 0 {
		if err := t.p.sleep(req.Context(), wait); err != nil {
			t.p.abandon(s)
			return nil, err
		}
		t.p.mu.Lock()
		hook := t.p.onWait
		t.p.mu.Unlock()
		if hook != nil {
			hook(req.Context(), host, wait)
		}
	}

	resp, err := t.base.RoundTrip(req)
	switch {
	case err != nil && req.Context().Err() != nil:
		// the caller gave up; that says nothing about the host
		t.p.abandon(s)
	case refused(resp, err):
		t.p.refusal(host, s, retryAfter(resp, t.p.now()))
	default:
		t.p.answer(host, s)
	}
	return resp, err
}

// admit decides whether a request may go and how long it must wait first.
func (p *Pacer) admit(host string, s *state) (time.Duration, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	now := p.now()
	if !s.openUntil.IsZero() {
		if now.Before(s.openUntil) || s.trial {
			return 0, fmt.Errorf("%w (%s)", ErrUnavailable, host)
		}
		// the cooldown is over: one trial request decides
		s.trial = true
	}

	var wait time.Duration
	if s.next.After(now) {
		wait = s.next.Sub(now)
	}
	// the next request waits at least the spacing after this one
	s.next = now.Add(wait + s.spacing)
	return wait, nil
}

// abandon releases a trial a caller gave up on.
func (p *Pacer) abandon(s *state) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.trial = false
}

func (p *Pacer) refusal(host string, s *state, after time.Duration) {
	s.mu.Lock()
	now := p.now()
	s.failures++
	switch {
	case s.spacing == 0:
		s.spacing = firstStep
	default:
		s.spacing = min(2*s.spacing, maxSpacing)
	}
	if next := now.Add(max(s.spacing, after)); next.After(s.next) {
		s.next = next
	}

	var opened bool
	var until time.Time
	switch {
	case s.trial:
		// the trial failed: stay open, longer
		s.trial = false
		s.cooldown = min(2*s.cooldown, maxCooldown)
		s.openUntil, opened, until = now.Add(s.cooldown), true, now.Add(s.cooldown)
	case s.openUntil.IsZero() && s.failures >= openAfter:
		s.openUntil, opened, until = now.Add(s.cooldown), true, now.Add(s.cooldown)
	}
	spacing := s.spacing
	s.mu.Unlock()

	if l := p.logger(); l != nil && opened {
		l.Warn("data source refusing requests; pausing it", "host", host, "until", until.UTC().Format(time.RFC3339),
			"consecutive_refusals", openAfter, "spacing", spacing.String())
	}
}

func (p *Pacer) answer(host string, s *state) {
	s.mu.Lock()
	closed := !s.openUntil.IsZero()
	s.failures, s.trial = 0, false
	s.openUntil, s.cooldown = time.Time{}, cooldown
	if s.spacing > 0 {
		s.spacing = time.Duration(float64(s.spacing) * recovery)
		if s.spacing < minSpacing {
			s.spacing = 0
		}
	}
	s.mu.Unlock()

	if l := p.logger(); l != nil && closed {
		l.Info("data source answering again; resuming it", "host", host)
	}
}

// refused reports whether a round trip was the host refusing for load: a
// 429, 502, 503 or 504, or a timeout or refused connection. Any other answer,
// a 404 or a 500 included, is an answer.
func refused(resp *http.Response, err error) bool {
	if err != nil {
		var ne net.Error
		if errors.As(err, &ne) && ne.Timeout() {
			return true
		}
		return errors.Is(err, context.DeadlineExceeded) || strings.Contains(err.Error(), "connection refused") ||
			strings.Contains(err.Error(), "connection reset")
	}
	if resp == nil {
		return false
	}
	switch resp.StatusCode {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable,
		http.StatusGatewayTimeout:
		return true
	}
	return false
}

// retryAfter reads a response's Retry-After (seconds or an HTTP date),
// capped at maxRetryAfter.
func retryAfter(resp *http.Response, now time.Time) time.Duration {
	if resp == nil {
		return 0
	}
	v := strings.TrimSpace(resp.Header.Get("Retry-After"))
	if v == "" {
		return 0
	}

	var d time.Duration
	if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
		d = time.Duration(secs) * time.Second
	} else if t, err := http.ParseTime(v); err == nil {
		d = t.Sub(now)
	}
	if d < 0 {
		return 0
	}
	return min(d, maxRetryAfter)
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
