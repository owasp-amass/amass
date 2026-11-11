// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ssh_probes

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"sync"

	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// outcome is what happened to one address the plugin was handed.
type outcome int

const (
	outcomeRecorded outcome = iota
	outcomeNoAnswer
	outcomeNotSSH
	outcomeNoHostKey
	outcomeStoreFailed
	outcomeAlreadyProbed
	outcomeOutOfScope
	outcomeReserved
	outcomePassive
	outcomeCount
)

// probedOutcomes are the outcomes of addresses a connection was attempted to.
var probedOutcomes = []outcome{outcomeRecorded, outcomeNoAnswer, outcomeNotSSH, outcomeNoHostKey, outcomeStoreFailed}

// outcomeKeys name each outcome in the session summary.
var outcomeKeys = [outcomeCount]string{"recorded", "no_answer", "not_ssh", "no_host_key", "store_failed",
	"already_probed", "out_of_scope", "reserved", "passive"}

// dialError marks a probe that could not connect.
type dialError struct{ err error }

func (d *dialError) Error() string { return d.err.Error() }
func (d *dialError) Unwrap() error { return d.err }

// probeOutcome classifies a probe that recorded no host key.
func probeOutcome(banner string, err error) outcome {
	var de *dialError
	switch {
	case banner != "":
		return outcomeNoHostKey
	case errors.As(err, &de):
		return outcomeNoAnswer
	default:
		return outcomeNotSSH
	}
}

// tally counts one session's outcomes.
type tally struct {
	mu     sync.Mutex
	counts [outcomeCount]int
}

func (t *tally) add(o outcome) {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.counts[o]++
}

func (t *tally) snapshot() [outcomeCount]int {
	t.mu.Lock()
	defer t.mu.Unlock()

	return t.counts
}

// summaries keeps a tally per session and logs it when the session ends, so
// a run shows whether SSH probing ran and why addresses got no host key.
type summaries struct {
	mu      sync.Mutex
	tallies map[uuid.UUID]*tally
	log     func() *slog.Logger
}

func newSummaries(log func() *slog.Logger) *summaries {
	return &summaries{tallies: make(map[uuid.UUID]*tally), log: log}
}

// record counts o for sess, starting the session's tally on first use.
func (s *summaries) record(sess et.Session, o outcome) {
	s.tallyFor(sess.ID(), sess.Ctx()).add(o)
}

func (s *summaries) tallyFor(id uuid.UUID, ctx context.Context) *tally {
	s.mu.Lock()
	defer s.mu.Unlock()

	t, ok := s.tallies[id]
	if !ok {
		t = &tally{}
		s.tallies[id] = t
		go s.logWhenDone(id, ctx, t)
	}

	return t
}

func (s *summaries) logWhenDone(id uuid.UUID, ctx context.Context, t *tally) {
	<-ctx.Done()
	s.flush(id, t)
}

// flush logs the summary for one session and forgets its tally.
func (s *summaries) flush(id uuid.UUID, t *tally) {
	s.mu.Lock()
	if s.tallies[id] != t {
		s.mu.Unlock()
		return
	}
	delete(s.tallies, id)
	s.mu.Unlock()

	msg, attrs := summary(t.snapshot())
	if l := s.log(); l != nil {
		l.Info(msg, append([]any{"session", id.String()}, attrs...)...)
	}
}

// flushAll logs every session still open, for when the plugin stops.
func (s *summaries) flushAll() {
	s.mu.Lock()
	open := make(map[uuid.UUID]*tally, len(s.tallies))
	for id, t := range s.tallies {
		open[id] = t
	}
	s.mu.Unlock()

	for id, t := range open {
		s.flush(id, t)
	}
}

// summary renders a session's counts as a log message and attributes.
func summary(c [outcomeCount]int) (string, []any) {
	var probed int
	for _, o := range probedOutcomes {
		probed += c[o]
	}

	var attrs []any
	for o, n := range c {
		if n > 0 {
			attrs = append(attrs, outcomeKeys[o], n)
		}
	}
	if probed == 0 && c[outcomePassive] > 0 {
		return "SSH host keys: none probed because active probing is off", attrs
	}

	return "SSH host keys recorded for " + strconv.Itoa(c[outcomeRecorded]) + " of " + strconv.Itoa(probed) + " probed addresses", attrs
}
