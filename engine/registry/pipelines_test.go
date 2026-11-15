// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type fakePlugin struct{ name string }

func (p *fakePlugin) Name() string { return p.name }

func (p *fakePlugin) Start(et.Registry) error { return nil }

func (p *fakePlugin) Stop() {}

// concurrency counts how many calls run at once.
type concurrency struct {
	sync.Mutex
	now, most int
	calls     atomic.Int64
}

func (c *concurrency) handler(d time.Duration, err error) func(*et.Event) error {
	return func(*et.Event) error {
		c.calls.Add(1)
		c.Lock()
		c.now++
		c.most = max(c.most, c.now)
		c.Unlock()

		time.Sleep(d)

		c.Lock()
		c.now--
		c.Unlock()
		return err
	}
}

func runEvents(t *testing.T, r *registry, sess *plugintest.Session, n int) ([]*et.EventDataElement, time.Duration) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	ap, err := r.BuildAssetPipeline(ctx, oam.IPAddress)
	if err != nil {
		t.Fatalf("the pipeline was not built: %v", err)
	}

	exit := make(chan *et.EventDataElement, n)
	start := time.Now()
	for i := range n {
		ip := &oamnet.IPAddress{Address: netip.AddrFrom4([4]byte{192, 0, 2, byte(i + 1)}), Type: "IPv4"}
		ede := et.NewEventDataElement(&et.Event{Name: ip.Key(), Entity: sess.Asset(t, ip), Session: sess})
		ede.Exit = exit
		if err := ap.Queue.Append(ede); err != nil {
			t.Fatalf("an event was not queued: %v", err)
		}
	}

	var out []*et.EventDataElement
	for range n {
		select {
		case ede := <-exit:
			out = append(out, ede)
		case <-time.After(10 * time.Second):
			t.Fatalf("only %d of %d events left the pipeline", len(out), n)
		}
	}

	return out, time.Since(start)
}

// Handlers sharing a position used to take one event at a time, so every
// address waited for the slowest probe of the address before it.
func TestSharedPositionHandlesEventsConcurrently(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil))).(*registry)
	var a, b concurrency
	for _, h := range []*et.Handler{
		{Plugin: &fakePlugin{"SSH-Probes"}, Name: "SSH-Probes-IPAddress-Interrogation", Position: 43,
			MaxInstances: 8, Transforms: []string{string(oam.Service)}, EventType: oam.IPAddress,
			Callback: a.handler(100*time.Millisecond, nil)},
		{Plugin: &fakePlugin{"Banner-Probes"}, Name: "Banner-Probes-IPAddress-Interrogation", Position: 43,
			MaxInstances: 4, Transforms: []string{string(oam.Service)}, EventType: oam.IPAddress,
			Callback: b.handler(100*time.Millisecond, errors.New("no greeting"))},
	} {
		if err := r.RegisterHandler(h); err != nil {
			t.Fatalf("the handler was not registered: %v", err)
		}
	}

	out, took := runEvents(t, r, sess, 16)
	if a.calls.Load() != 16 || b.calls.Load() != 16 {
		t.Fatalf("each handler should see every event: %d and %d calls", a.calls.Load(), b.calls.Load())
	}
	// four at a time, the fewer of the two handlers' instances
	if b.most != 4 || a.most != 4 {
		t.Errorf("the stage ran %d and %d events at once, expected 4", a.most, b.most)
	}
	if took > 1200*time.Millisecond {
		t.Errorf("16 events of 100ms, four at a time, took %v", took)
	}
	for _, ede := range out {
		if ede.Error == nil || !strings.Contains(ede.Error.Error(), "no greeting") {
			t.Errorf("a handler's error was not kept on the event: %v", ede.Error)
		}
	}
}

func TestSingleInstanceHandlerKeepsStageSerial(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil))).(*registry)
	var a, b concurrency
	for _, h := range []*et.Handler{
		{Plugin: &fakePlugin{"A"}, Name: "A-Handler", Position: 5, MaxInstances: 16,
			Transforms: []string{
				string(oam.Service),
			}, EventType: oam.IPAddress, Callback: a.handler(10*time.Millisecond, nil)},
		{Plugin: &fakePlugin{"B"}, Name: "B-Handler", Position: 5,
			Transforms: []string{
				string(oam.Service),
			}, EventType: oam.IPAddress, Callback: b.handler(10*time.Millisecond, nil)},
	} {
		if err := r.RegisterHandler(h); err != nil {
			t.Fatalf("the handler was not registered: %v", err)
		}
	}

	out, _ := runEvents(t, r, sess, 6)
	if a.most != 1 || b.most != 1 {
		t.Errorf("a handler allowing one instance ran beside itself: %d, %d at once", a.most, b.most)
	}
	for _, ede := range out {
		if ede.Error != nil {
			t.Errorf("an event picked up an error: %v", ede.Error)
		}
	}
}
