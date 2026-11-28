// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"errors"
	"io"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// trace records the order handlers ran in for each event.
type trace struct {
	sync.Mutex
	seen map[string][]string
}

func (tr *trace) handler(name string, d time.Duration, c *concurrency, err error) func(*et.Event) error {
	return func(e *et.Event) error {
		if c != nil {
			_ = c.handler(d, nil)(e)
		} else {
			time.Sleep(d)
		}
		tr.Lock()
		if tr.seen == nil {
			tr.seen = map[string][]string{}
		}
		tr.seen[e.Name] = append(tr.seen[e.Name], name)
		tr.Unlock()
		return err
	}
}

func newPhasedRegistry(t *testing.T, hs ...*et.Handler) *registry {
	t.Helper()
	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil))).(*registry)
	for _, h := range hs {
		h.EventType = oam.IPAddress
		h.Transforms = []string{string(oam.Service)}
		if err := r.RegisterHandler(h); err != nil {
			t.Fatalf("the handler was not registered: %v", err)
		}
	}
	return r
}

func TestPhaseOf(t *testing.T) {
	for pos, want := range map[int]string{0: "resolve", 2: "resolve", 11: "resolve", 12: "collect", 39: "collect",
		40: "probe", 49: "probe", 50: "derive", 51: "derive"} {
		if got := PhaseOf(pos); got != want {
			t.Errorf("PhaseOf(%d) = %q, want %q", pos, got, want)
		}
	}
}

// Sources at different positions of one phase run at the same time, so an
// event waits for the slowest, not for their sum; the resolve phase still
// runs before them, and derive after.
func TestPhaseRunsPluginsTogether(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	var tr trace
	var a, b, c concurrency
	r := newPhasedRegistry(t,
		&et.Handler{Plugin: &fakePlugin{"DNS"}, Name: "DNS-Handler", Position: 2, MaxInstances: 4,
			Callback: tr.handler("resolve", 0, nil, nil)},
		&et.Handler{Plugin: &fakePlugin{"Source-A"}, Name: "A-Handler", Position: 22, MaxInstances: 4,
			Callback: tr.handler("a", 100*time.Millisecond, &a, nil)},
		&et.Handler{Plugin: &fakePlugin{"Source-B"}, Name: "B-Handler", Position: 30, MaxInstances: 4,
			Callback: tr.handler("b", 100*time.Millisecond, &b, nil)},
		&et.Handler{Plugin: &fakePlugin{"Source-C"}, Name: "C-Handler", Position: 37, MaxInstances: 4,
			Callback: tr.handler("c", 100*time.Millisecond, &c, errors.New("rate limited"))},
		&et.Handler{Plugin: &fakePlugin{"Attribution"}, Name: "Attribution-Handler", Position: 50, MaxInstances: 4,
			Callback: tr.handler("derive", 0, nil, nil)},
	)

	out, took := runBuiltEvents(t, r.BuildPhasedPipeline, sess, 8)
	// eight events, four at a time, 100ms each: about 200ms when the three
	// sources overlap, about 600ms when they run one after another
	if took > 450*time.Millisecond {
		t.Errorf("8 events through three 100ms sources took %v", took)
	}
	if a.most != 4 || b.most != 4 || c.most != 4 {
		t.Errorf("each source should run 4 events at once: %d, %d, %d", a.most, b.most, c.most)
	}
	for name, order := range tr.seen {
		if len(order) != 5 || order[0] != "resolve" || order[4] != "derive" {
			t.Errorf("%s ran %v; resolve must come first and derive last", name, order)
		}
	}
	if len(out) != 8 {
		t.Fatalf("%d events left the pipeline, want 8", len(out))
	}
	for _, ede := range out {
		if ede.Error == nil || !strings.Contains(ede.Error.Error(), "rate limited") {
			t.Errorf("a handler's error was not kept on the event: %v", ede.Error)
		}
	}
}

// One plugin's handlers keep their position order inside a phase, and a
// handler allowing one instance runs one event at a time.
func TestPhaseKeepsPluginOrder(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	var tr trace
	var single concurrency
	company := &fakePlugin{"Company"}
	r := newPhasedRegistry(t,
		&et.Handler{Plugin: company, Name: "Company-Enrich", Position: 43, MaxInstances: 4,
			Callback: tr.handler("enrich", 0, nil, nil)},
		&et.Handler{Plugin: company, Name: "Company-Search", Position: 41, MaxInstances: 4,
			Callback: tr.handler("search", 20*time.Millisecond, nil, nil)},
		&et.Handler{Plugin: &fakePlugin{"Probe"}, Name: "Probe-Handler", Position: 42,
			Callback: tr.handler("probe", 10*time.Millisecond, &single, nil)},
	)

	out, _ := runBuiltEvents(t, r.BuildPhasedPipeline, sess, 6)
	if len(out) != 6 {
		t.Fatalf("%d events left the pipeline, want 6", len(out))
	}
	if single.most != 1 {
		t.Errorf("a handler allowing one instance ran %d events at once", single.most)
	}
	for name, order := range tr.seen {
		if i, j := slices.Index(order, "search"), slices.Index(order, "enrich"); i < 0 || j < i {
			t.Errorf("%s ran %v; the plugin's position 41 handler must come before its 43", name, order)
		}
	}
}

// An event whose session ends while it is in a phase leaves the pipeline,
// and no later handler runs on it. (Events still queued for a session that
// has ended are dropped by the pipeline's queue.)
func TestPhaseLetsDoneEventsOut(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	r := newPhasedRegistry(t,
		&et.Handler{Plugin: &fakePlugin{"Ender"}, Name: "Ender-Handler", Position: 20, MaxInstances: 2,
			Callback: func(*et.Event) error { sess.Kill(); return nil }},
		&et.Handler{Plugin: &fakePlugin{"Later"}, Name: "Later-Handler", Position: 45, MaxInstances: 2,
			Callback: func(*et.Event) error { t.Error("a handler ran after the session ended"); return nil }},
	)

	if out, _ := runBuiltEvents(t, r.BuildPhasedPipeline, sess, 1); len(out) != 1 {
		t.Fatalf("%d events left the pipeline, want 1", len(out))
	}
}
