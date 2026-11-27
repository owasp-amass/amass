// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dispatcher

import (
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/caffix/queue"
	"github.com/google/uuid"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// fakeBacklog keeps each entity's state in memory, in the order enqueued.
type fakeBacklog struct {
	mu         sync.Mutex
	order      []*dbt.Entity
	state      map[string]string
	enqueues   int
	enqueueErr error
	acked      []string
	released   []string
}

func newFakeBacklog() *fakeBacklog { return &fakeBacklog{state: map[string]string{}} }

func (b *fakeBacklog) Has(e *dbt.Entity) bool {
	b.mu.Lock()
	defer b.mu.Unlock()

	_, ok := b.state[e.ID]
	return ok
}

func (b *fakeBacklog) Enqueue(e *dbt.Entity) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	if b.enqueueErr != nil {
		return b.enqueueErr
	}
	b.enqueues++
	if _, ok := b.state[e.ID]; !ok {
		b.order = append(b.order, e)
	}
	b.state[e.ID] = "queued"
	return nil
}

func (b *fakeBacklog) ClaimNext(atype oam.AssetType, num int) ([]*dbt.Entity, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	var out []*dbt.Entity
	for _, e := range b.order {
		if len(out) == num {
			break
		}
		if e.Asset.AssetType() == atype && b.state[e.ID] == "queued" {
			b.state[e.ID] = "leased"
			out = append(out, e)
		}
	}
	if len(out) == 0 {
		return nil, errors.New("no entities claimed")
	}
	return out, nil
}

func (b *fakeBacklog) Ack(e *dbt.Entity, _ bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.state[e.ID] = "done"
	b.acked = append(b.acked, e.ID)
	return nil
}

func (b *fakeBacklog) Release(e *dbt.Entity, _ oam.AssetType, _ bool) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.state[e.ID] = "queued"
	b.released = append(b.released, e.ID)
	return nil
}

func (b *fakeBacklog) Counts(atype oam.AssetType) (queued, leased, done int64, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	for _, e := range b.order {
		if e.Asset.AssetType() != atype {
			continue
		}
		switch b.state[e.ID] {
		case "queued":
			queued++
		case "leased":
			leased++
		case "done":
			done++
		}
	}
	return
}

func (b *fakeBacklog) Close() error { return nil }

// fakeSession is the part of et.Session the dispatcher uses.
type fakeSession struct {
	et.Session
	id        uuid.UUID
	backlog   *fakeBacklog
	pipelines et.SessionPipelines
}

func newFakeSession() *fakeSession {
	pipes := et.SessionPipelines{}
	for _, atype := range oam.AssetList {
		pipes[atype] = &et.AssetPipeline{Queue: et.NewPipelineQueue()}
	}
	return &fakeSession{id: uuid.New(), backlog: newFakeBacklog(), pipelines: pipes}
}

func (s *fakeSession) ID() uuid.UUID                               { return s.id }
func (s *fakeSession) Backlog() et.Backlog                         { return s.backlog }
func (s *fakeSession) Pipelines() et.SessionPipelines              { return s.pipelines }
func (s *fakeSession) Log() *slog.Logger                           { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
func (s *fakeSession) Done() bool                                  { return false }
func (s *fakeSession) queue(atype oam.AssetType) *et.PipelineQueue { return s.pipelines[atype].Queue }

type fakeManager struct {
	et.SessionManager
	sessions []et.Session
}

func (m *fakeManager) GetSessions() []et.Session { return m.sessions }

// newTestDispatcher builds the dispatcher without its background
// goroutines, so each test drives the steps itself.
func newTestDispatcher(sessions ...*fakeSession) *dispatcher {
	mgr := &fakeManager{}
	for _, s := range sessions {
		mgr.sessions = append(mgr.sessions, s)
	}
	return &dispatcher{
		log:      slog.New(slog.NewTextHandler(io.Discard, nil)),
		mgr:      mgr,
		done:     make(chan struct{}),
		wake:     make(chan oam.AssetType, 1),
		cchan:    make(chan *et.EventDataElement, 1000),
		cqueue:   queue.NewQueue(),
		meta:     newMetaMap(),
		shuffler: rand.New(rand.NewSource(1)),
	}
}

func fqdn(id int) *dbt.Entity {
	return &dbt.Entity{ID: fmt.Sprint(id), Asset: &oamdns.FQDN{Name: fmt.Sprintf("host%d.example.com", id)}}
}

func woken(d *dispatcher) (oam.AssetType, bool) {
	select {
	case atype := <-d.wake:
		return atype, true
	default:
		return "", false
	}
}

func TestDispatchEventSchedulesEachEntityOnce(t *testing.T) {
	sess := newFakeSession()
	d := newTestDispatcher(sess)

	for _, bad := range []*et.Event{nil, {Session: sess}, {Entity: fqdn(1)}} {
		if err := d.DispatchEvent(bad); err == nil {
			t.Errorf("the incomplete event %+v was accepted", bad)
		}
	}

	ent := fqdn(1)
	if err := d.DispatchEvent(&et.Event{Entity: ent, Session: sess, Meta: "first"}); err != nil {
		t.Fatal(err)
	}
	if atype, ok := woken(d); !ok || atype != oam.FQDN {
		t.Errorf("the pump was not woken for the FQDN: %v, %t", atype, ok)
	}
	if meta, err := d.meta.GetEntry(sess.id.String(), ent.ID); err != nil || meta != "first" {
		t.Errorf("the event metadata = %v, %v", meta, err)
	}

	// The same entity again is neither enqueued nor given new metadata.
	if err := d.DispatchEvent(&et.Event{Entity: ent, Session: sess, Meta: "second"}); err != nil {
		t.Fatal(err)
	}
	if sess.backlog.enqueues != 1 {
		t.Errorf("enqueued %d times, want once", sess.backlog.enqueues)
	}
	if meta, _ := d.meta.GetEntry(sess.id.String(), ent.ID); meta != "first" {
		t.Errorf("the metadata became %v", meta)
	}
	if _, ok := woken(d); ok {
		t.Error("the pump was woken for an entity already scheduled")
	}
}

func TestDispatchEventDropsTheMetadataWhenEnqueueFails(t *testing.T) {
	sess := newFakeSession()
	sess.backlog.enqueueErr = errors.New("disk full")
	d := newTestDispatcher(sess)

	ent := fqdn(1)
	if err := d.DispatchEvent(&et.Event{Entity: ent, Session: sess, Meta: "meta"}); err == nil {
		t.Fatal("the enqueue failure was not returned")
	}
	if _, err := d.meta.GetEntry(sess.id.String(), ent.ID); err == nil {
		t.Error("the metadata was kept for an entity that was not enqueued")
	}
}

func TestDispatchEventLeavesABusyPipelineAsleep(t *testing.T) {
	sess := newFakeSession()
	d := newTestDispatcher(sess)

	low := limitsByAssetType(oam.FQDN).LowWater
	for i := 0; i <= low; i++ {
		_ = sess.queue(oam.FQDN).Append(et.NewEventDataElement(&et.Event{}))
	}
	if err := d.DispatchEvent(&et.Event{Entity: fqdn(1), Session: sess}); err != nil {
		t.Fatal(err)
	}
	if _, ok := woken(d); ok {
		t.Errorf("the pump was woken with %d events already queued", low+1)
	}
}

func TestPumpOnceFillsThePipelineInBursts(t *testing.T) {
	sess := newFakeSession()
	d := newTestDispatcher(sess)

	for i := 1; i <= 15; i++ {
		ent := fqdn(i)
		if err := d.DispatchEvent(&et.Event{Entity: ent, Session: sess, Meta: i}); err != nil {
			t.Fatal(err)
		}
	}

	burst := limitsByAssetType(oam.FQDN).PerSessBurst
	d.pumpOnce(oam.FQDN)
	q := sess.queue(oam.FQDN)
	if q.Len() != burst {
		t.Fatalf("queued %d events, want a burst of %d", q.Len(), burst)
	}
	if queued, leased, _, _ := sess.backlog.Counts(oam.FQDN); queued != int64(15-burst) || leased != int64(burst) {
		t.Errorf("backlog = %d queued, %d leased", queued, leased)
	}

	// Each event carries its metadata and comes back to the dispatcher.
	for i := 1; i <= burst; i++ {
		ede, ok := q.Data().(*et.EventDataElement)
		if !ok {
			t.Fatalf("event %d is missing", i)
		}
		ev := ede.Event
		if ev.Entity.ID != fmt.Sprint(i) || ev.Meta != i || ev.Dispatcher != d || ev.Session != sess {
			t.Errorf("event %d = %+v", i, ev)
		}
		if ev.Name != "FQDN: "+fmt.Sprintf("host%d.example.com", i) {
			t.Errorf("event %d is named %q", i, ev.Name)
		}
		if ede.Exit != d.cchan || ede.Ref != sess.pipelines[oam.FQDN] {
			t.Errorf("event %d does not return to the dispatcher's pipeline", i)
		}
	}

	// The next pump claims the rest.
	d.pumpOnce(oam.FQDN)
	if q.Len() != 15-burst {
		t.Errorf("the second pump queued %d events, want %d", q.Len(), 15-burst)
	}
}

func TestPumpOnceKeepsThePipelineUnderItsLimit(t *testing.T) {
	sess := newFakeSession()
	d := newTestDispatcher(sess)

	lim := limitsByAssetType(oam.FQDN)
	q := sess.queue(oam.FQDN)
	for q.Len() < lim.MaxQueued-3 {
		_ = q.Append(et.NewEventDataElement(&et.Event{}))
	}
	for i := 1; i <= 10; i++ {
		_ = d.DispatchEvent(&et.Event{Entity: fqdn(i), Session: sess})
	}

	d.pumpOnce(oam.FQDN)
	if q.Len() != lim.MaxQueued {
		t.Errorf("the pipeline holds %d events, want its limit of %d", q.Len(), lim.MaxQueued)
	}

	// A full pipeline takes nothing more.
	d.pumpOnce(oam.FQDN)
	if queued, _, _, _ := sess.backlog.Counts(oam.FQDN); queued != 7 {
		t.Errorf("%d entities left queued, want 7", queued)
	}
}

func TestPumpOnceReleasesWhatADrainingPipelineRefuses(t *testing.T) {
	sess := newFakeSession()
	d := newTestDispatcher(sess)

	for i := 1; i <= 3; i++ {
		_ = d.DispatchEvent(&et.Event{Entity: fqdn(i), Session: sess})
	}
	sess.queue(oam.FQDN).Drain()

	d.pumpOnce(oam.FQDN)
	if n := len(sess.backlog.released); n != 3 {
		t.Errorf("released %d entities, want 3", n)
	}
	if queued, leased, _, _ := sess.backlog.Counts(oam.FQDN); queued != 3 || leased != 0 {
		t.Errorf("backlog = %d queued, %d leased; the refused entities should be queued", queued, leased)
	}
}

func TestPumpOnceServesEverySession(t *testing.T) {
	a, b := newFakeSession(), newFakeSession()
	d := newTestDispatcher(a, b)

	_ = d.DispatchEvent(&et.Event{Entity: fqdn(1), Session: a})
	_ = d.DispatchEvent(&et.Event{Entity: fqdn(2), Session: b})

	d.pumpOnce(oam.FQDN)
	if a.queue(oam.FQDN).Len() != 1 || b.queue(oam.FQDN).Len() != 1 {
		t.Errorf("queued %d and %d events, want one per session",
			a.queue(oam.FQDN).Len(), b.queue(oam.FQDN).Len())
	}
}

func TestCompletedEventsAreAckedAndWakeThePump(t *testing.T) {
	sess := newFakeSession()
	d := newTestDispatcher(sess)

	ent := fqdn(1)
	_ = d.DispatchEvent(&et.Event{Entity: ent, Session: sess, Meta: "meta"})
	_, _ = woken(d)
	d.pumpOnce(oam.FQDN)

	ede := sess.queue(oam.FQDN).Data().(*et.EventDataElement)
	ede.Error = errors.New("a handler failed")
	d.completedCallback(ede)

	if len(sess.backlog.acked) != 1 || sess.backlog.acked[0] != ent.ID {
		t.Errorf("acked %v", sess.backlog.acked)
	}
	if _, err := d.meta.GetEntry(sess.id.String(), ent.ID); err == nil {
		t.Error("the metadata outlived the event")
	}
	if atype, ok := woken(d); !ok || atype != oam.FQDN {
		t.Errorf("the emptied pipeline did not wake the pump: %v, %t", atype, ok)
	}
}

func TestRemoveKilledSessionsDropsTheirMetadata(t *testing.T) {
	live, killed := newFakeSession(), newFakeSession()
	d := newTestDispatcher(live)

	_ = d.meta.InsertEntry(live.id.String(), "1", "kept")
	_ = d.meta.InsertEntry(killed.id.String(), "2", "dropped")

	d.removeKilledSessions()
	if _, err := d.meta.GetEntry(live.id.String(), "1"); err != nil {
		t.Errorf("the live session lost its metadata: %v", err)
	}
	if _, err := d.meta.GetEntry(killed.id.String(), "2"); err == nil {
		t.Error("the killed session kept its metadata")
	}
}

// Every finished event is acked, however many finish at once: more than the
// completion channel holds are handed back while the acks run.
func TestEveryCompletedEventIsAcked(t *testing.T) {
	sess := newFakeSession()
	d := newTestDispatcher(sess)
	go d.collectCompletedEvents()
	go d.processCompletedEvents()
	t.Cleanup(d.Shutdown)

	const n = 2500
	go func() {
		for i := 0; i < n; i++ {
			d.cchan <- et.NewEventDataElement(&et.Event{Entity: fqdn(i), Session: sess})
		}
	}()

	deadline := time.Now().Add(10 * time.Second)
	for {
		sess.backlog.mu.Lock()
		acked := len(sess.backlog.acked)
		sess.backlog.mu.Unlock()
		if acked == n {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%d of %d finished events were acked", acked, n)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
