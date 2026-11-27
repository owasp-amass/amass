// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/engine/api/client"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
)

// admitLeaseTTL is how long a worker's lease on deciding an asset lasts
// unless renewed; it is renewed while the decider works.
const admitLeaseTTL = time.Minute

// remotePoll is how often a worker waiting on another's decision checks
// whether it arrived. A variable so tests can shorten it.
var remotePoll = time.Second

// admissionRecord is an admission record's data: a decision a decider made,
// with the evidence it was made on.
type admissionRecord struct {
	Worker     string          `json:"worker"`
	Key        string          `json:"key"`
	EntityID   string          `json:"entity_id"`
	Type       string          `json:"type"`
	Asset      json.RawMessage `json:"asset"`
	Outcome    string          `json:"outcome"`
	Confidence int             `json:"confidence,omitempty"`
	DecidedBy  string          `json:"decided_by"`
	Rationale  string          `json:"rationale,omitempty"`
	Conclusion string          `json:"conclusion,omitempty"`
	Evidence   []string        `json:"evidence,omitempty"`
}

// publishAdmission shares a decision a decider made. Matching and the
// policy give every worker the same answer, so theirs are not shared.
func (s *Scope) publishAdmission(d *et.AdmissionDecision, evidence []string) {
	a := d.Asset()
	if a == nil || d.DecidedBy == "matching" || d.DecidedBy == "policy" {
		return
	}
	raw, err := json.Marshal(a)
	if err != nil {
		return
	}

	s.appendRecord(AdmissionKind, a.Key(), func(worker string) any {
		return admissionRecord{Worker: worker, Key: admissionKey(a), EntityID: d.Request.Entity.ID,
			Type: string(a.AssetType()), Asset: raw, Outcome: string(d.Outcome), Confidence: d.Confidence,
			DecidedBy: d.DecidedBy, Rationale: d.Rationale, Conclusion: string(d.Conclusion), Evidence: evidence}
	})
}

// admitLease takes the job's lease on deciding the asset with key, and
// reports whether this worker holds it. Without a job, it always does.
func (s *Scope) admitLease(ctx context.Context, key string) (release func(), ok bool) {
	r := s.rep.Load()
	if r == nil || r.leases == nil {
		return func() {}, true
	}
	return r.leases.Hold(ctx, "admit:"+r.job+":"+key, admitLeaseTTL)
}

// awaitRemote waits for the decision another worker is making, which the
// follower applies, and rejects the asset as undecided when none arrives in
// time.
func (s *Scope) awaitRemote(ctx context.Context, id, by string) {
	deadline := time.NewTimer(AdmissionTimeout)
	defer deadline.Stop()
	tick := time.NewTicker(remotePoll)
	defer tick.Stop()

	for {
		if d := s.Decision(id); d == nil || d.Outcome != et.Pending {
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-deadline.C:
			s.settle(id, et.AdmissionVerdict{Outcome: et.Rejected,
				Rationale: "undecided: the worker deciding it gave no answer"}, by, false)
			return
		case <-tick.C:
		}
	}
}

// applyAdmission takes another worker's decision. An admitted asset stays
// admitted; a rejection only adds the evidence it was decided on, so the
// asset is decided again only on new evidence; a decision this worker was
// waiting for is given to its requester and waiters.
func (s *Scope) applyAdmission(ar *admissionRecord) {
	outcome := et.AdmissionOutcome(ar.Outcome)
	if outcome != et.Admitted && outcome != et.Rejected {
		return
	}

	s.adm.Lock()
	if s.adm.byAsset == nil {
		s.adm.byAsset = map[string]*admissionEntry{}
		s.adm.byID = map[string]*admissionEntry{}
	}
	e, ok := s.adm.byAsset[ar.Key]
	if ok && (e.decision.Outcome == et.Admitted || (e.decision.Outcome == et.Rejected && outcome == et.Rejected)) {
		for _, k := range ar.Evidence {
			e.seen[k] = true
		}
		s.adm.Unlock()
		return
	}

	id, pending := uuid.NewString(), ok && e.decision.Outcome == et.Pending
	var req *et.AdmissionRequest
	switch {
	case pending:
		id, req = e.decision.ID, e.decision.Request
	case ok:
		req = e.decision.Request
		delete(s.adm.byID, e.decision.ID)
	default:
		a, err := client.ParseAsset(ar.Type, ar.Asset)
		if err != nil {
			s.adm.Unlock()
			return
		}
		req = &et.AdmissionRequest{Entity: &dbt.Entity{ID: ar.EntityID, Asset: a}}
		e = &admissionEntry{seen: map[string]bool{}}
		s.adm.byAsset[ar.Key] = e
	}
	for _, k := range ar.Evidence {
		e.seen[k] = true
	}
	d := &et.AdmissionDecision{ID: id, Request: req, Outcome: outcome, Confidence: ar.Confidence,
		DecidedBy: ar.DecidedBy, Rationale: ar.Rationale, Conclusion: et.AdmissionOutcome(ar.Conclusion),
		At: time.Now()}
	e.decision = d
	s.adm.byID[id] = e
	waiters := e.waiters
	e.waiters = nil
	s.adm.Unlock()

	if !pending {
		return
	}
	if req.OnDecided != nil {
		req.OnDecided(d)
	}
	for _, fn := range waiters {
		fn(d)
	}
}
