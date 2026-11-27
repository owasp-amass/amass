// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"io"
	"log/slog"
	"sync/atomic"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// laterDecider decides every request once release is closed.
type laterDecider struct{ release chan struct{} }

func (d laterDecider) Name() string { return "later" }

func (d laterDecider) Decide(context.Context, et.Session, *et.AdmissionRequest) (et.AdmissionVerdict, bool, error) {
	return et.AdmissionVerdict{Outcome: et.Pending, Later: func(ctx context.Context) (et.AdmissionVerdict, error) {
		select {
		case <-d.release:
			return et.AdmissionVerdict{Outcome: et.Admitted, Confidence: 90}, nil
		case <-ctx.Done():
			return et.AdmissionVerdict{}, ctx.Err()
		}
	}}, true, nil
}

// A handler waiting on an admission decision does not hold its worker or the
// event: the event leaves the pipeline at once, and the handler is called
// again with it once the decision is made.
func TestHandlerParksUntilAdmissionIsDecided(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	release := make(chan struct{})
	sess.Scope().(*scope.Scope).SetAdmissionDeciders(laterDecider{release: release})
	related := sess.Asset(t, &oamdns.FQDN{Name: "related.org"})

	var calls atomic.Int64
	var decided atomic.Value
	r := NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil))).(*registry)
	if err := r.RegisterHandler(&et.Handler{Plugin: &fakePlugin{"Expander"}, Name: "Expander-IPAddress",
		Position: 5, MaxInstances: 1, Transforms: []string{string(oam.Service)}, EventType: oam.IPAddress,
		Callback: func(e *et.Event) error {
			calls.Add(1)
			d, err := e.Session.Scope().Admit(&et.AdmissionRequest{Entity: related, Via: "IPAddress->FQDN",
				Evidence: []et.AdmissionEvidence{{Signal: "test"}}})
			if err != nil {
				return err
			}
			if d.Outcome == et.Pending {
				return &et.PendingError{DecisionID: d.ID}
			}
			decided.Store(d.Outcome)
			return nil
		}}); err != nil {
		t.Fatal(err)
	}

	out, _ := runEvents(t, r, sess, 1)
	if out[0].Error != nil {
		t.Errorf("waiting is not an error: %v", out[0].Error)
	}
	if calls.Load() != 1 || sess.Stats().Background() < 1 {
		t.Fatalf("calls %d, background %d", calls.Load(), sess.Stats().Background())
	}

	close(release)
	for deadline := time.Now().Add(5 * time.Second); calls.Load() < 2 || sess.Stats().Background() != 0; {
		if time.Now().After(deadline) {
			t.Fatalf("the handler was not resumed: calls %d, background %d", calls.Load(),
				sess.Stats().Background())
		}
		time.Sleep(5 * time.Millisecond)
	}
	if decided.Load() != et.Admitted {
		t.Errorf("the resumed handler saw %v", decided.Load())
	}
}
