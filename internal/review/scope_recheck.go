// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"sort"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// Reevaluation for horizontal scope expansion, the counterpart of
// RecheckRelations. Every applied expansion records the witness edges the
// scored decision rested on; a re-check re-tests that witness as the Asset
// Database changes during (and after) an enumeration. When a witnessed
// relationship is gone the expansion no longer holds: one the engine added on
// its own is retracted (recorded with RecheckReviewer, so a later return of the
// evidence re-applies it), while one a person approved is reopened as a pending
// proposal for re-review rather than undone — a human decision stays sticky
// (ai-design-principles.md, principle 9). Nothing enumerated is deleted; only
// whether the domain stays in scope on the next run changes, and the change is
// surfaced for review.

// ScopeRecheckResult lists what a scope-expansion re-check changed.
type ScopeRecheckResult struct {
	Checked   int              `json:"checked"`
	Retracted []ScopeExpansion `json:"retracted,omitempty"`
	Flagged   []ScopeExpansion `json:"flagged,omitempty"`
}

// RecheckScopeExpansions re-tests every applied horizontal scope expansion
// against the witness it recorded. See the note above for what reopening means.
func RecheckScopeExpansions(ctx context.Context, g graph.Graph, j *Journal) (ScopeRecheckResult, error) {
	return recheckScopeExpansions(ctx, j, func(w []graph.WitnessEdge) (string, error) {
		return missingWitness(ctx, g, w)
	})
}

func recheckScopeExpansions(ctx context.Context, j *Journal, check witnessChecker) (ScopeRecheckResult, error) {
	var res ScopeRecheckResult

	applied, err := j.AppliedScopeExpansions()
	if err != nil {
		return res, err
	}
	sort.Slice(applied, func(a, b int) bool { return applied[a].ID < applied[b].ID })

	for _, e := range applied {
		if len(e.Witness) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}
		res.Checked++

		missing, err := check(e.Witness)
		if err != nil {
			return res, err
		}
		if missing == "" {
			continue
		}

		if isAIReviewer(e.Reviewer) {
			if err := j.RecordScopeExpansion(ScopeExpansion{ID: e.ID, OrgID: e.OrgID, Org: e.Org, Domain: e.Domain,
				Status: ProposalRetracted, Reviewer: RecheckReviewer}); err != nil {
				return res, err
			}
			res.Retracted = append(res.Retracted, e)
		} else {
			// A person approved it: reopen as a pending proposal for re-review
			// rather than undoing a human decision.
			if err := j.RecordScopeExpansion(ScopeExpansion{ID: e.ID, OrgID: e.OrgID, Org: e.Org, Domain: e.Domain,
				Confidence: e.Confidence, Signals: e.Signals, SignalIDs: e.SignalIDs, Witness: e.Witness,
				Status: ProposalPending}); err != nil {
				return res, err
			}
			res.Flagged = append(res.Flagged, e)
		}
	}

	return res, nil
}

// ScopeExpansionRedecidable reports whether a scope expansion can be re-applied
// automatically: it is still pending, or it was retracted by a re-check (not by
// a person). A person's rejection or retraction is sticky.
func ScopeExpansionRedecidable(status, reviewer string) bool {
	return status == ProposalPending ||
		(status == ProposalRetracted && reviewer == RecheckReviewer)
}
