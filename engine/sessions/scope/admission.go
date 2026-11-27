// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// AdmissionTimeout bounds how long a decider working in the background (a
// model call) may take; a request still undecided then is rejected, and a
// later request with new evidence is decided again. A variable so tests can
// shorten it.
var AdmissionTimeout = 2 * time.Minute

// admissions is the scope's admission authority: its decisions, by asset and
// by ID, the callbacks waiting on pending ones, and the deciders and recorder
// the session gives it.
type admissions struct {
	sync.Mutex
	byAsset  map[string]*admissionEntry
	byID     map[string]*admissionEntry
	deciders []et.AdmissionDecider
	record   func(*et.AdmissionDecision)
	// entries are the scope entries admissions added, so the scope the run
	// was given can be told from what it admitted (et.InScope versus
	// et.StandingAdmitted).
	entries map[string]bool
}

type admissionEntry struct {
	decision *et.AdmissionDecision
	// seen is the evidence already decided on (signals and cited assets), so a
	// rejected asset is decided again only when new evidence arrives.
	seen    map[string]bool
	waiters []func(*et.AdmissionDecision)
}

func admissionKey(a oam.Asset) string {
	return string(a.AssetType()) + "|" + a.Key()
}

// evidenceKeys are the evidence's signals and cited assets.
func evidenceKeys(req *et.AdmissionRequest) []string {
	var keys []string
	for _, ev := range req.Evidence {
		if ev.Signal != "" {
			keys = append(keys, "signal:"+ev.Signal)
		}
		for _, c := range ev.Cites {
			if c != nil {
				keys = append(keys, "cite:"+c.ID)
			}
		}
	}
	return keys
}

// SetAdmissionDeciders sets the deciders the scope asks, in order, about a
// request that matching and the policy do not settle.
func (s *Scope) SetAdmissionDeciders(ds ...et.AdmissionDecider) {
	s.adm.Lock()
	defer s.adm.Unlock()
	s.adm.deciders = ds
}

// SetAdmissionRecorder sets the function given every decision once it is
// made, such as one writing the review journal.
func (s *Scope) SetAdmissionRecorder(fn func(*et.AdmissionDecision)) {
	s.adm.Lock()
	defer s.adm.Unlock()
	s.adm.record = fn
}

// Admit implements et.Admitter. In order: a blacklisted asset, or an asset
// reached through a transformation whose confidence is above 100
// (config.NeverAdmit), is rejected by the policy; an asset that matches the scope
// is admitted by matching; an asset already admitted, or pending, keeps that
// decision; an asset rejected before is decided again only on new evidence;
// otherwise the deciders are asked in turn, and a request none of them takes
// is decided on its evidence (evidenceVerdict).
func (s *Scope) Admit(req *et.AdmissionRequest) (*et.AdmissionDecision, error) {
	if req == nil || req.Entity == nil || req.Entity.Asset == nil {
		return nil, errors.New("an admission request needs a stored asset")
	}
	a := req.Entity.Asset
	key := admissionKey(a)

	s.adm.Lock()
	if e, ok := s.adm.byAsset[key]; ok && e.decision.Outcome != et.Rejected {
		d := e.decision
		s.adm.Unlock()
		return d, nil
	} else if ok && !hasNew(e.seen, evidenceKeys(req)) {
		d := e.decision
		s.adm.Unlock()
		return d, nil
	}
	deciders := s.adm.deciders
	s.adm.Unlock()

	switch {
	case s.IsBlacklisted(a):
		return s.decide(req, et.AdmissionVerdict{Outcome: et.Rejected, Rationale: "the asset is blacklisted"},
			"policy"), nil
	}
	// every path below meets the policy's confidence: the deciders are told
	// it, and the evidence rule applies it
	req.PolicyConfidence = s.policyConfidence(a.AssetType(), req.Via)
	if req.PolicyConfidence >= config.NeverAdmit {
		return s.decide(req, et.AdmissionVerdict{Outcome: et.Rejected,
			Rationale: "the expansion policy never admits through " + via(req)}, "policy"), nil
	}
	if match, conf := s.IsAssetInScope(a, 100); match != nil && conf > 0 {
		return s.decide(req, et.AdmissionVerdict{Outcome: et.Admitted, Confidence: conf,
			Rationale: fmt.Sprintf("it matches %s %s in scope", match.AssetType(), match.Key())}, "matching"), nil
	}

	ctx := context.Background()
	if s.Session != nil {
		ctx = s.Session.Ctx()
	}
	for _, d := range deciders {
		v, ok, err := d.Decide(ctx, s.Session, req)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", d.Name(), err)
		}
		if !ok {
			continue
		}
		if v.Outcome == et.Pending && v.Later != nil {
			return s.pend(ctx, req, d.Name(), v.Later), nil
		}
		return s.decide(req, v, d.Name()), nil
	}

	return s.decide(req, s.evidenceVerdict(req), "evidence"), nil
}

// evidenceVerdict admits an asset on strong evidence whose confidence meets
// the policy: the confidence the configuration gives the asset's type for the
// transformation or plugin that reached it. Supporting evidence alone is left
// for review.
func (s *Scope) evidenceVerdict(req *et.AdmissionRequest) et.AdmissionVerdict {
	var strong []string
	for _, ev := range req.Evidence {
		if ev.Strength == et.StrengthStrong {
			strong = append(strong, ev.Signal)
		}
	}
	if len(strong) == 0 {
		return et.AdmissionVerdict{Outcome: et.Rejected, Confidence: req.Confidence,
			Rationale: "only supporting evidence; left for review"}
	}

	// Strong evidence with no score is a rule (a registrant's organization,
	// an in-scope AS's announcement): it counts as certain, and only a policy
	// that never admits refuses it.
	conf := req.Confidence
	if conf == 0 {
		conf = 100
	}
	if need := req.PolicyConfidence; need > 0 && conf < need {
		return et.AdmissionVerdict{Outcome: et.Rejected, Confidence: conf,
			Rationale: fmt.Sprintf("confidence %d is below the policy's %d", conf, need)}
	}
	return et.AdmissionVerdict{Outcome: et.Admitted, Confidence: conf,
		Rationale: "strong evidence: " + strings.Join(strong, ", ")}
}

// via names how a request's asset was reached, for a rationale.
func via(req *et.AdmissionRequest) string {
	if req.Via != "" {
		return req.Via
	}
	return string(req.Entity.Asset.AssetType())
}

// policyConfidence is the confidence the configuration requires to admit an
// asset of the type reached through via (a plugin name or a target type):
// the TYPE->via transformation's, then the type's own, or -1.
func (s *Scope) policyConfidence(atype oam.AssetType, via string) int {
	if s.Session == nil || s.Session.Config() == nil {
		return -1
	}
	t := string(atype)
	matches, err := s.Session.Config().CheckTransformations(t, t, via)
	if err != nil || matches == nil {
		return -1
	}
	if via != "" {
		if conf := matches.Confidence(via); conf > 0 {
			return conf
		}
	}
	if conf := matches.Confidence(t); conf > 0 {
		return conf
	}
	return -1
}

func hasNew(seen map[string]bool, keys []string) bool {
	for _, k := range keys {
		if !seen[k] {
			return true
		}
	}
	return false
}

// pend records a pending decision and runs the decider's later work in the
// background, as session background work so the session is not finished
// while it runs.
func (s *Scope) pend(ctx context.Context, req *et.AdmissionRequest, by string,
	later func(context.Context) (et.AdmissionVerdict, error)) *et.AdmissionDecision {
	d := s.decide(req, et.AdmissionVerdict{Outcome: et.Pending, Rationale: "being decided"}, by)
	if d.Outcome != et.Pending {
		return d
	}
	if s.Session != nil && s.Session.Stats() != nil {
		s.Session.Stats().AddBackground(1)
	}

	go func() {
		if s.Session != nil && s.Session.Stats() != nil {
			defer s.Session.Stats().AddBackground(-1)
		}
		// one worker of a job decides an asset; the others wait for its record
		release, mine := s.admitLease(ctx, admissionKey(req.Entity.Asset))
		if !mine {
			s.awaitRemote(ctx, d.ID, by)
			return
		}
		defer release()

		lctx, cancel := context.WithTimeout(ctx, AdmissionTimeout)
		defer cancel()

		v, err := later(lctx)
		switch {
		case err != nil:
			v = et.AdmissionVerdict{Outcome: et.Rejected, Rationale: "undecided: " + err.Error()}
		case v.Outcome == et.Pending:
			v = et.AdmissionVerdict{Outcome: et.Rejected, Rationale: "undecided: the decider gave no answer"}
		}
		s.settle(d.ID, v, by, true)
	}()
	return d
}

// decide records a new decision for the request's asset.
func (s *Scope) decide(req *et.AdmissionRequest, v et.AdmissionVerdict, by string) *et.AdmissionDecision {
	d := &et.AdmissionDecision{ID: uuid.NewString(), Request: req, Outcome: v.Outcome, Confidence: v.Confidence,
		DecidedBy: by, Rationale: v.Rationale, Conclusion: v.Conclusion, At: time.Now()}
	key := admissionKey(req.Entity.Asset)

	s.adm.Lock()
	if s.adm.byAsset == nil {
		s.adm.byAsset = map[string]*admissionEntry{}
		s.adm.byID = map[string]*admissionEntry{}
	}
	e, ok := s.adm.byAsset[key]
	if ok && (e.decision.Outcome == et.Admitted || e.decision.Outcome == et.Pending) {
		// another request decided it first
		d = e.decision
		s.adm.Unlock()
		return d
	}
	if !ok {
		e = &admissionEntry{seen: map[string]bool{}}
		s.adm.byAsset[key] = e
	} else {
		delete(s.adm.byID, e.decision.ID)
	}
	for _, k := range evidenceKeys(req) {
		e.seen[k] = true
	}
	e.decision = d
	s.adm.byID[d.ID] = e
	s.adm.Unlock()

	if d.Outcome != et.Pending {
		s.finish(e, d, true)
	}
	return d
}

// settle turns a pending decision into its verdict; publish shares it with
// the job's other workers.
func (s *Scope) settle(id string, v et.AdmissionVerdict, by string, publish bool) {
	s.adm.Lock()
	e, ok := s.adm.byID[id]
	if !ok || e.decision.Outcome != et.Pending {
		s.adm.Unlock()
		return
	}
	d := *e.decision
	d.Outcome, d.Confidence, d.Rationale, d.Conclusion, d.At = v.Outcome, v.Confidence, v.Rationale, v.Conclusion,
		time.Now()
	e.decision = &d
	s.adm.Unlock()

	s.finish(e, &d, publish)
}

// finish acts on a made decision: an admitted asset joins the scope and is
// queued for another look; the decision is recorded, and, when publish is
// set, shared with the job's other workers; waiters are told.
func (s *Scope) finish(e *admissionEntry, d *et.AdmissionDecision, publish bool) {
	if d.Outcome == et.Admitted && d.DecidedBy != "matching" {
		if e := entryOf(d.Request.Entity.Asset); e != nil {
			s.addEntry(e, true, true)
		}
		if s.Session != nil && s.Session.Backlog() != nil {
			_ = s.Session.Backlog().Enqueue(d.Request.Entity)
		}
		// cached standings are stale, and held assets may now be in
		go s.grown()
	}

	s.adm.Lock()
	record := s.adm.record
	waiters := e.waiters
	e.waiters = nil
	evidence := make([]string, 0, len(e.seen))
	for k := range e.seen {
		evidence = append(evidence, k)
	}
	s.adm.Unlock()

	if publish {
		s.publishAdmission(d, evidence)
	}

	if record != nil {
		record(d)
	}
	if d.Request.OnDecided != nil {
		d.Request.OnDecided(d)
	}
	for _, fn := range waiters {
		fn(d)
	}
}

// Await implements et.Admitter.
func (s *Scope) Await(id string, fn func(*et.AdmissionDecision)) bool {
	s.adm.Lock()
	defer s.adm.Unlock()

	e, ok := s.adm.byID[id]
	if !ok || e.decision.Outcome != et.Pending || fn == nil {
		return false
	}
	e.waiters = append(e.waiters, fn)
	return true
}

// Decision implements et.Admitter.
func (s *Scope) Decision(id string) *et.AdmissionDecision {
	s.adm.Lock()
	defer s.adm.Unlock()

	if e, ok := s.adm.byID[id]; ok {
		return e.decision
	}
	return nil
}

// Standing implements et.Admitter.
func (s *Scope) Standing(a oam.Asset) et.Standing {
	if a == nil {
		return et.Unconsidered
	}
	s.adm.Lock()
	defer s.adm.Unlock()
	if !s.IsBlacklisted(a) {
		if match, conf := s.IsAssetInScope(a, 100); match != nil && conf > 0 {
			if s.adm.entries[admissionKey(match)] {
				return et.StandingAdmitted
			}
			return et.InScope
		}
	}

	e, ok := s.adm.byAsset[admissionKey(a)]
	if !ok {
		return et.Unconsidered
	}
	switch e.decision.Outcome {
	case et.Admitted:
		return et.StandingAdmitted
	case et.Pending:
		return et.StandingPending
	}
	return et.StandingRejected
}
