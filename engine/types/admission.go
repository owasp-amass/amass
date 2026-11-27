// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import (
	"context"
	"fmt"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Admission into scope. Plugins propose; the session's scope decides. A plugin
// that finds evidence an asset belongs to the target sends an
// AdmissionRequest with that evidence, never a verdict, and the scope applies
// the configuration's policy, scores the evidence and records the decision,
// so every widening of scope is made the same way and can be explained and
// undone. Matching (a name under an in-scope domain, an address in an
// in-scope netblock) needs no request: it is a rule, not a decision.

// AdmissionOutcome is what became of a request.
type AdmissionOutcome string

const (
	// Admitted: the asset is in scope, by matching or by decision.
	Admitted AdmissionOutcome = "admitted"
	// Rejected: the evidence was not enough, or the policy forbids it. A
	// later request with new evidence is decided again.
	Rejected AdmissionOutcome = "rejected"
	// Pending: a decider is still working (a classifier or model); the
	// decision follows, and Await reports it.
	Pending AdmissionOutcome = "pending"
)

// AdmissionEvidence is one piece of evidence that ties the asset to the
// target: a signal from the signal catalogs and the stored assets it cites.
type AdmissionEvidence struct {
	// Signal is the catalog ID of the signal, such as "shared-registrant-org".
	Signal string
	// Cites are the stored assets that show it, such as the shared
	// registration record.
	Cites []*dbt.Entity
	// Strength is the signal's strength: StrengthStrong or
	// StrengthSupporting. Supporting evidence alone does not admit an asset
	// unless a decider (a trained model) says so.
	Strength string
	// Detail is a short readable description, for the decision's rationale.
	Detail string
}

// Evidence strengths.
const (
	StrengthStrong     = "strong"
	StrengthSupporting = "supporting"
)

// Signals the engine itself finds, beside those of the signal catalogs.
const (
	// SignalAssociation: the asset is related to an asset with associative
	// value (a registrant, a certificate subject) that is in scope.
	SignalAssociation = "scope-association"
	// SignalSharedContactRecord: the asset is named by the same contact
	// record as an in-scope asset, such as the registrant organization of an
	// in-scope domain.
	SignalSharedContactRecord = "shared-contact-record"
	// SignalAnnouncedByScopeAS: an in-scope autonomous system announces the
	// netblock.
	SignalAnnouncedByScopeAS = "announced-by-in-scope-as"
	// SignalOwnershipAttribution: automatic attribution placed the asset
	// under an in-scope organization.
	SignalOwnershipAttribution = "ownership-attribution"
)

// AdmissionRequest asks for an asset to be admitted into scope.
type AdmissionRequest struct {
	// Entity is the stored asset proposed for scope.
	Entity *dbt.Entity
	// For is the in-scope organization the evidence ties the asset to, when
	// there is one.
	For *dbt.Entity
	// Via names how the asset was reached: a transformation ("FQDN->DNS") or a
	// plugin name. The policy for that transformation applies.
	Via string
	// Evidence is what ties the asset to the target.
	Evidence []AdmissionEvidence
	// Confidence is the requester's own score for the evidence (0..100),
	// when it has one, such as the weighted horizontal signals.
	Confidence int
	// Source is the plugin making the request.
	Source *Source
	// PolicyConfidence is the confidence the expansion policy requires to
	// admit the asset (its transformation's confidence), set by the scope
	// for the deciders; a decider admits only at or above it.
	PolicyConfidence int
	// OnDecided, when set, is called with the decision once it is made, so
	// the requester can record it with its own details or act on it.
	OnDecided func(*AdmissionDecision)
}

// AdmissionDecision is the scope's answer to a request.
type AdmissionDecision struct {
	// ID identifies the decision, for Await and the journal.
	ID      string
	Request *AdmissionRequest
	Outcome AdmissionOutcome
	// Confidence is the decided score (0..100).
	Confidence int
	// DecidedBy names what decided: "matching", "policy", a decider's name
	// such as "horizontal-signals", or a model ("model qwen3:30b").
	DecidedBy string
	Rationale string
	// Conclusion is the decider's own answer, when a model gave one: it
	// can differ from Outcome, as when the model would admit but below the
	// policy's confidence. Empty when no model answered (a rule decided, or
	// the model failed).
	Conclusion AdmissionOutcome
	At         time.Time
}

// Asset returns the asset the decision is about.
func (d *AdmissionDecision) Asset() oam.Asset {
	if d == nil || d.Request == nil || d.Request.Entity == nil {
		return nil
	}
	return d.Request.Entity.Asset
}

// AdmissionVerdict is a decider's answer. A decider that needs time (a model
// call) returns Pending with Later, which the scope runs in the background
// and whose verdict becomes the decision.
type AdmissionVerdict struct {
	Outcome    AdmissionOutcome
	Confidence int
	Rationale  string
	// Conclusion is a model's own answer (AdmissionDecision.Conclusion).
	Conclusion AdmissionOutcome
	Later      func(ctx context.Context) (AdmissionVerdict, error)
}

// AdmissionDecider decides requests of the kinds it knows. Decide returns
// ok false to leave a request to the next decider.
type AdmissionDecider interface {
	Name() string
	Decide(ctx context.Context, sess Session, req *AdmissionRequest) (v AdmissionVerdict, ok bool, err error)
}

// Admitter is the session scope's admission authority.
type Admitter interface {
	// Admit decides a request: at once, or Pending while a decider works.
	Admit(req *AdmissionRequest) (*AdmissionDecision, error)
	// Await calls fn with the decision once it is made and reports true; it
	// reports false, without calling fn, when the decision is already made
	// or is unknown.
	Await(id string, fn func(*AdmissionDecision)) bool
	// Decision returns the decision with the ID, or nil.
	Decision(id string) *AdmissionDecision
	// Standing reports where an asset stands: in scope by matching,
	// admitted, pending, rejected, or not yet considered (Unconsidered).
	Standing(a oam.Asset) Standing
	// StandingOf reports where a stored asset stands, including one the
	// scope cannot judge by itself, which takes the standing of the assets
	// it hangs off; NotGoverned for a type the expansion policy does not
	// govern.
	StandingOf(e *dbt.Entity) Standing
	// ConnectedWithin reports whether the asset is linked to the footprint
	// within hops relations.
	ConnectedWithin(e *dbt.Entity, hops int) bool
	// Hold remembers an asset the expansion policy kept from a handler, so
	// it is queued again once the scope grows to take it in.
	Hold(e *dbt.Entity)
}

// Standing is where an asset stands with the scope.
type Standing string

const (
	// InScope: the asset matches the scope (a rule, no decision).
	InScope Standing = "in_scope"
	// StandingAdmitted: a decision admitted it.
	StandingAdmitted Standing = "admitted"
	// StandingPending: a decision is being made.
	StandingPending Standing = "pending"
	// StandingRejected: a decision kept it out.
	StandingRejected Standing = "rejected"
	// Unconsidered: no request has been made for it.
	Unconsidered Standing = "unconsidered"
	// NotGoverned: the expansion policy does not govern the asset's type
	// (semantics standing.json), so reach does not apply to it.
	NotGoverned Standing = "not_governed"
)

// PendingError is returned by a handler that cannot go on until an admission
// is decided. The pipeline parks the handler's event, the handler's worker
// takes the next event, and the handler is called again with the event once
// the decision is made. Handlers that return it must be safe to call again
// for the same event (their TTL checks make most of them so).
type PendingError struct {
	DecisionID string
}

func (e *PendingError) Error() string {
	return fmt.Sprintf("waiting for admission decision %s", e.DecisionID)
}
