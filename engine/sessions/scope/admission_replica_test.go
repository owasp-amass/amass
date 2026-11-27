// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/coord"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// modelDecider rejects at once, or, given later, answers in the background
// with what later sends, counting the calls to its background work.
type modelDecider struct {
	calls, background atomic.Int32
	later             chan et.AdmissionOutcome
}

func (d *modelDecider) Name() string { return "model test" }

func (d *modelDecider) Decide(context.Context, et.Session, *et.AdmissionRequest) (et.AdmissionVerdict, bool, error) {
	d.calls.Add(1)
	if d.later == nil {
		return et.AdmissionVerdict{Outcome: et.Rejected, Rationale: "not related"}, true, nil
	}
	return et.AdmissionVerdict{Outcome: et.Pending, Later: func(ctx context.Context) (et.AdmissionVerdict, error) {
		d.background.Add(1)
		select {
		case o := <-d.later:
			return et.AdmissionVerdict{Outcome: o, Confidence: 85, Rationale: "the model says so", Conclusion: o}, nil
		case <-ctx.Done():
			return et.AdmissionVerdict{}, ctx.Err()
		}
	}}, true, nil
}

func fqdnRequest(id, name, signal string) *et.AdmissionRequest {
	return &et.AdmissionRequest{Entity: &dbt.Entity{ID: id, Asset: &oamdns.FQDN{Name: name}}, Via: "test",
		Evidence: []et.AdmissionEvidence{{Signal: signal}}}
}

// workers are two scopes of one job on a shared journal and leases, each
// with its own lease holder, as two engines would be.
func workers() (a, b *Scope, store *coord.FakeLeases, topic *coord.Topic) {
	topic = &coord.Topic{Store: &coord.FakeStore{}, Name: "work"}
	store = &coord.FakeLeases{}
	a, b = New(nil).(*Scope), New(nil).(*Scope)
	a.Replicate(topic, &coord.Leases{Store: store, Holder: "a"}, "job", "a")
	b.Replicate(topic, &coord.Leases{Store: store, Holder: "b"}, "job", "b")
	return a, b, store, topic
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for end := time.Now().Add(5 * time.Second); time.Now().Before(end); time.Sleep(10 * time.Millisecond) {
		if cond() {
			return
		}
	}
	t.Fatalf("timed out waiting for %s", what)
}

// A worker's rejection reaches the others, which decide the asset again
// only on new evidence.
func TestRejectionsAreSharedByTheJobsWorkers(t *testing.T) {
	a, b, _, topic := workers()
	da, db := &modelDecider{}, &modelDecider{}
	a.SetAdmissionDeciders(da)
	b.SetAdmissionDeciders(db)

	if d, err := a.Admit(fqdnRequest("1", "other.org", "shared-favicon")); err != nil || d.Outcome != et.Rejected {
		t.Fatalf("a decided %+v, %v", d, err)
	}
	applyAll(t, b, topic)
	if st := b.Standing(&oamdns.FQDN{Name: "other.org"}); st != et.StandingRejected {
		t.Fatalf("other.org stands %v for b", st)
	}

	d, _ := b.Admit(fqdnRequest("1", "other.org", "shared-favicon"))
	if d.Outcome != et.Rejected || d.DecidedBy != "model test" || db.calls.Load() != 0 {
		t.Errorf("b decided again on the same evidence: %+v, %d calls", d, db.calls.Load())
	}
	if _, _ = b.Admit(fqdnRequest("1", "other.org", "shared-registrant")); db.calls.Load() != 1 {
		t.Errorf("b did not decide on new evidence: %d calls", db.calls.Load())
	}
}

// One worker asks the model about an asset; the other waits for its answer
// and gives it to its own requester.
func TestOneWorkerAsksTheModel(t *testing.T) {
	a, b, store, topic := workers()
	da := &modelDecider{later: make(chan et.AdmissionOutcome, 1)}
	db := &modelDecider{later: make(chan et.AdmissionOutcome, 1)}
	a.SetAdmissionDeciders(da)
	b.SetAdmissionDeciders(db)

	ad, _ := a.Admit(fqdnRequest("2", "acme-cdn.net", "shared-registrant"))
	if ad.Outcome != et.Pending {
		t.Fatalf("a decided %+v", ad)
	}
	lease := "admit:job:FQDN|acme-cdn.net"
	waitFor(t, "a's lease", func() bool { return store.Holder(lease) == "a" })

	var told atomic.Value
	breq := fqdnRequest("2", "acme-cdn.net", "shared-registrant")
	breq.OnDecided = func(d *et.AdmissionDecision) { told.Store(d) }
	bd, _ := b.Admit(breq)
	if bd.Outcome != et.Pending {
		t.Fatalf("b decided %+v", bd)
	}
	time.Sleep(50 * time.Millisecond)
	if n := db.background.Load(); n != 0 {
		t.Fatalf("b asked the model too (%d)", n)
	}

	da.later <- et.Admitted
	waitFor(t, "a's decision", func() bool { return a.Decision(ad.ID).Outcome == et.Admitted })
	applyAll(t, b, topic)
	if d := b.Decision(bd.ID); d.Outcome != et.Admitted || d.DecidedBy != "model test" {
		t.Errorf("b has %+v", d)
	}
	if d, _ := told.Load().(*et.AdmissionDecision); d == nil || d.Outcome != et.Admitted {
		t.Errorf("b's requester was told %+v", d)
	}
	if st := b.Standing(&oamdns.FQDN{Name: "acme-cdn.net"}); st != et.StandingAdmitted {
		t.Errorf("acme-cdn.net stands %v for b", st)
	}
	waitFor(t, "the lease's release", func() bool { return store.Holder(lease) == "" })
}

// A worker waiting on another that never answers rejects the asset as
// undecided, without telling the others.
func TestAWorkerThatNeverAnswers(t *testing.T) {
	saved := AdmissionTimeout
	AdmissionTimeout = 100 * time.Millisecond
	t.Cleanup(func() { AdmissionTimeout = saved })

	_, b, store, _ := workers()
	gone := &coord.Leases{Store: store, Holder: "gone"}
	if !gone.Try("admit:job:FQDN|stuck.example", time.Hour) {
		t.Fatal("the lease was not taken")
	}
	db := &modelDecider{later: make(chan et.AdmissionOutcome, 1)}
	b.SetAdmissionDeciders(db)

	bd, _ := b.Admit(fqdnRequest("3", "stuck.example", "shared-registrant"))
	waitFor(t, "the timeout", func() bool { return b.Decision(bd.ID).Outcome != et.Pending })
	if d := b.Decision(bd.ID); d.Outcome != et.Rejected || !strings.HasPrefix(d.Rationale, "undecided") {
		t.Errorf("b has %+v", d)
	}
	if db.background.Load() != 0 {
		t.Error("b asked the model while another worker held the lease")
	}
}
