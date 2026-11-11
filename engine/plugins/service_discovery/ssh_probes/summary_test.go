// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ssh_probes

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestProbeOutcome(t *testing.T) {
	refused := &dialError{err: errors.New("connection refused")}
	cases := []struct {
		name   string
		banner string
		err    error
		want   outcome
	}{
		{"no connection", "", refused, outcomeNoAnswer},
		{"wrapped dial error", "", errors.Join(errors.New("probe"), refused), outcomeNoAnswer},
		{"connected but not SSH", "", errors.New("ssh: handshake failed: EOF"), outcomeNotSSH},
		{"SSH without a usable key", "SSH-2.0-OpenSSH_9.6", errors.New("no common algorithm"), outcomeNoHostKey},
	}
	for _, c := range cases {
		if got := probeOutcome(c.banner, c.err); got != c.want {
			t.Errorf("%s: got %s, want %s", c.name, outcomeKeys[got], outcomeKeys[c.want])
		}
	}
}

// A refused port is dialed once and reported as a dial failure, not as a
// non-SSH service.
func TestHostKeysMarksDialFailure(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := l.Addr().String()
	_ = l.Close()

	var d net.Dialer
	var dials int
	dial := func(ctx context.Context, network, address string) (net.Conn, error) {
		dials++
		return d.DialContext(ctx, network, address)
	}

	banner, keys, err := hostKeys(context.Background(), dial, addr)
	if len(keys) != 0 {
		t.Fatalf("got keys %v from a closed port", keys)
	}
	if dials != 1 {
		t.Fatalf("dialed a closed port %d times, want 1", dials)
	}
	if got := probeOutcome(banner, err); got != outcomeNoAnswer {
		t.Fatalf("got %s for a closed port, want no_answer (err %v)", outcomeKeys[got], err)
	}
}

// A listener that speaks something other than SSH is not_ssh.
func TestHostKeysMarksNonSSH(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			_, _ = c.Write([]byte("HTTP/1.1 400 Bad Request\r\n\r\n"))
			_ = c.Close()
		}
	}()

	var d net.Dialer
	banner, keys, err := hostKeys(context.Background(), d.DialContext, l.Addr().String())
	if len(keys) != 0 {
		t.Fatalf("got keys %v from a non-SSH service", keys)
	}
	if got := probeOutcome(banner, err); got != outcomeNotSSH {
		t.Fatalf("got %s for a non-SSH service, want not_ssh (err %v)", outcomeKeys[got], err)
	}
}

func TestSummaryMessage(t *testing.T) {
	var c [outcomeCount]int
	c[outcomeRecorded] = 2
	c[outcomeNoAnswer] = 7
	c[outcomeNotSSH] = 1
	c[outcomeOutOfScope] = 40
	msg, attrs := summary(c)
	if msg != "SSH host keys recorded for 2 of 10 probed addresses" {
		t.Errorf("got %q", msg)
	}
	want := []any{"recorded", 2, "no_answer", 7, "not_ssh", 1, "out_of_scope", 40}
	if len(attrs) != len(want) {
		t.Fatalf("got attrs %v, want %v", attrs, want)
	}
	for i := range want {
		if attrs[i] != want[i] {
			t.Fatalf("got attrs %v, want %v", attrs, want)
		}
	}

	var passive [outcomeCount]int
	passive[outcomePassive] = 5
	if msg, _ := summary(passive); !strings.Contains(msg, "active probing is off") {
		t.Errorf("passive session: got %q", msg)
	}
}

type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// Each session's summary is logged once, when that session ends, and only
// sessions still open are logged when the plugin stops.
func TestSummariesPerSession(t *testing.T) {
	var buf syncBuffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	s := newSummaries(func() *slog.Logger { return logger })

	ended, endedCancel := context.WithCancel(context.Background())
	open, openCancel := context.WithCancel(context.Background())
	defer openCancel()

	a, b := uuid.New(), uuid.New()
	s.tallyFor(a, ended).add(outcomeRecorded)
	s.tallyFor(a, ended).add(outcomeNoAnswer)
	s.tallyFor(b, open).add(outcomeNoAnswer)

	endedCancel()
	deadline := time.Now().Add(2 * time.Second)
	for !strings.Contains(buf.String(), a.String()) {
		if time.Now().After(deadline) {
			t.Fatal("the ended session's summary was not logged")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !strings.Contains(buf.String(), "recorded for 1 of 2 probed addresses") {
		t.Fatalf("ended session summary: %s", buf.String())
	}
	if strings.Contains(buf.String(), b.String()) {
		t.Fatal("the open session was logged before it ended")
	}

	s.flushAll()
	s.flushAll()
	out := buf.String()
	if strings.Count(out, a.String()) != 1 || strings.Count(out, b.String()) != 1 {
		t.Fatalf("each session should be logged exactly once:\n%s", out)
	}
	if !strings.Contains(out, "recorded for 0 of 1 probed addresses") {
		t.Fatalf("open session summary: %s", out)
	}
}
