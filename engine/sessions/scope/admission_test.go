// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/sessions/scope"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

// decider admits or rejects every request, at once or later.
type decider struct {
	outcome et.AdmissionOutcome
	later   chan et.AdmissionOutcome // when set, the verdict waits for a value
	calls   int
}

func (d *decider) Name() string { return "test-decider" }

func (d *decider) Decide(_ context.Context, _ et.Session, _ *et.AdmissionRequest) (et.AdmissionVerdict, bool, error) {
	d.calls++
	if d.later == nil {
		return et.AdmissionVerdict{Outcome: d.outcome, Confidence: 90, Rationale: "test"}, true, nil
	}
	return et.AdmissionVerdict{Outcome: et.Pending, Later: func(ctx context.Context) (et.AdmissionVerdict, error) {
		select {
		case o := <-d.later:
			return et.AdmissionVerdict{Outcome: o, Confidence: 80, Rationale: "decided later", Conclusion: o}, nil
		case <-ctx.Done():
			return et.AdmissionVerdict{}, ctx.Err()
		}
	}}, true, nil
}

func request(t *testing.T, sess *plugintest.Session, name, signal string) *et.AdmissionRequest {
	t.Helper()
	return &et.AdmissionRequest{Entity: sess.Asset(t, &oamdns.FQDN{Name: name}), Via: "Organization->FQDN",
		Evidence: []et.AdmissionEvidence{{Signal: signal}}}
}

func TestAdmitByMatchingAndPolicy(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.Scope().AddDomain("example.com")

	d, err := sess.Scope().Admit(request(t, sess, "www.example.com", "any"))
	if err != nil || d.Outcome != et.Admitted || d.DecidedBy != "matching" {
		t.Fatalf("a name under an in-scope domain: %+v, %v", d, err)
	}
	if got := sess.Scope().Standing(&oamdns.FQDN{Name: "www.example.com"}); got != et.InScope {
		t.Errorf("standing = %s, want in_scope", got)
	}

	// With no decider, evidence decides: supporting evidence alone is left
	// for review, strong evidence admits.
	d, _ = sess.Scope().Admit(request(t, sess, "other.org", "shared-favicon"))
	if d.Outcome != et.Rejected || d.DecidedBy != "evidence" {
		t.Errorf("supporting evidence: %+v", d)
	}
	strong := request(t, sess, "other.org", "shared-registrant-org")
	strong.Evidence[0].Strength = et.StrengthStrong
	if d, _ = sess.Scope().Admit(strong); d.Outcome != et.Admitted || d.DecidedBy != "evidence" {
		t.Errorf("strong evidence: %+v", d)
	}

	// A policy that never admits keeps the scope as given, whatever a decider
	// would say.
	sess.Scope().(*scope.Scope).SetAdmissionDeciders(&decider{outcome: et.Admitted})
	sess.TTL(60)
	sess.Config().ApplyStrictPolicy()
	d, _ = sess.Scope().Admit(request(t, sess, "strict.org", "shared-registrant-org"))
	if d.Outcome != et.Rejected || !strings.Contains(d.Rationale, "never admits") {
		t.Errorf("strict policy: %+v", d)
	}
}

// Every path meets the policy's confidence: a scored request below it is
// refused, and a rule with no score is counted as certain.
func TestAdmissionMeetsThePolicy(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)
	sess.Config().Transformations["fqdn->all"].Confidence = 90

	low := request(t, sess, "low.org", "shared-registrant-org")
	low.Evidence[0].Strength, low.Confidence = et.StrengthStrong, 80
	if d, _ := sess.Scope().Admit(low); d.Outcome != et.Rejected || !strings.Contains(d.Rationale, "below the policy's 90") {
		t.Errorf("a score below the policy: %+v", d)
	}
	rule := request(t, sess, "rule.org", et.SignalSharedContactRecord)
	rule.Evidence[0].Strength = et.StrengthStrong
	if d, _ := sess.Scope().Admit(rule); d.Outcome != et.Admitted || d.Confidence != 100 {
		t.Errorf("a rule with no score: %+v", d)
	}
}

func TestAdmitByDecider(t *testing.T) {
	sess := plugintest.NewSession(t)
	sc := sess.Scope().(*scope.Scope)
	dec := &decider{outcome: et.Rejected}
	var recorded []*et.AdmissionDecision
	sc.SetAdmissionDeciders(dec)
	sc.SetAdmissionRecorder(func(d *et.AdmissionDecision) { recorded = append(recorded, d) })

	first, _ := sc.Admit(request(t, sess, "related.org", "shared-registrant-org"))
	if first.Outcome != et.Rejected || first.DecidedBy != "test-decider" {
		t.Fatalf("decision = %+v", first)
	}
	// The same evidence is not decided again.
	again, _ := sc.Admit(request(t, sess, "related.org", "shared-registrant-org"))
	if again.ID != first.ID || dec.calls != 1 {
		t.Errorf("the same evidence was decided again: %d calls", dec.calls)
	}

	// New evidence is.
	dec.outcome = et.Admitted
	d, _ := sc.Admit(request(t, sess, "related.org", "cert-subject-org"))
	if d.Outcome != et.Admitted || dec.calls != 2 {
		t.Fatalf("new evidence: %+v, %d calls", d, dec.calls)
	}
	if got := sc.Standing(&oamdns.FQDN{Name: "www.related.org"}); got != et.StandingAdmitted {
		t.Errorf("an admitted domain joins the scope, as admitted: standing %s", got)
	}
	if !sess.Backlog().Has(d.Request.Entity) {
		t.Error("an admitted asset is queued for another look")
	}
	if len(recorded) != 2 || recorded[1].ID != d.ID {
		t.Errorf("recorded %d decisions", len(recorded))
	}
}

func TestAdmitLater(t *testing.T) {
	sess := plugintest.NewSession(t)
	sc := sess.Scope().(*scope.Scope)
	dec := &decider{later: make(chan et.AdmissionOutcome)}
	sc.SetAdmissionDeciders(dec)

	d, _ := sc.Admit(request(t, sess, "maybe.org", "shared-analytics-id"))
	if d.Outcome != et.Pending || sc.Standing(&oamdns.FQDN{Name: "maybe.org"}) != et.StandingPending {
		t.Fatalf("decision = %+v", d)
	}
	if sess.Stats().Background() != 1 {
		t.Errorf("a pending decision is background work: %d", sess.Stats().Background())
	}

	var wg sync.WaitGroup
	wg.Add(1)
	var got *et.AdmissionDecision
	if !sc.Await(d.ID, func(made *et.AdmissionDecision) { got = made; wg.Done() }) {
		t.Fatal("Await refused a pending decision")
	}
	dec.later <- et.Admitted
	wg.Wait()

	if got.Outcome != et.Admitted || got.ID != d.ID || sc.Decision(d.ID).Outcome != et.Admitted ||
		got.Conclusion != et.Admitted {
		t.Errorf("decided %+v", got)
	}
	if sc.Await(d.ID, func(*et.AdmissionDecision) {}) {
		t.Error("Await accepted a decision already made")
	}
	waitFor(t, func() bool { return sess.Stats().Background() == 0 })
}

func TestAdmitLaterTimesOut(t *testing.T) {
	defer func(d time.Duration) { scope.AdmissionTimeout = d }(scope.AdmissionTimeout)
	scope.AdmissionTimeout = 20 * time.Millisecond

	sess := plugintest.NewSession(t)
	sc := sess.Scope().(*scope.Scope)
	sc.SetAdmissionDeciders(&decider{later: make(chan et.AdmissionOutcome)})

	d, _ := sc.Admit(request(t, sess, "slow.org", "shared-favicon"))
	waitFor(t, func() bool { return sc.Decision(d.ID).Outcome != et.Pending })
	if made := sc.Decision(d.ID); made.Outcome != et.Rejected || !strings.Contains(made.Rationale, "undecided") {
		t.Errorf("an undecided request: %+v", made)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if cond() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the condition was not met in time")
}
