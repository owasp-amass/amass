// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"sort"
	"time"
)

// RecheckReviewer is the reviewer recorded when an automatic write is
// retracted because its evidence is gone. Unlike a person's retraction, it
// does not stop the relationship from being written again once evidence
// supports it.
const RecheckReviewer = "amass-ai (re-check)"

// OwnershipRetractor removes a relationship written from a proposal and
// reports whether the edge was deleted (rather than only its amass-ai
// source).
type OwnershipRetractor interface {
	RetractOwnership(ctx context.Context, edgeID string) (bool, error)
}

// RecheckResult lists the automatic writes a re-check retracted.
type RecheckResult struct {
	Checked   int                 `json:"checked"`
	Retracted []OwnershipProposal `json:"retracted"`
}

// RecheckAttributions re-tests every relationship automatic attribution
// wrote against the evidence its proposal recorded. When a relationship
// that evidence was read from no longer exists, the write is retracted and
// recorded with RecheckReviewer; the next attribution pass writes it again
// if the remaining evidence still supports it. Writes a person approved
// are left alone.
func RecheckAttributions(ctx context.Context, graph Graph, r OwnershipRetractor, j *Journal) (RecheckResult, error) {
	var res RecheckResult
	state, err := j.OwnershipState()
	if err != nil {
		return res, err
	}

	ids := make([]string, 0, len(state))
	for id := range state {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		e := state[id]
		if e.Status != ProposalApplied || e.Outcome == nil || e.Outcome.Reviewer != AutomaticReviewer ||
			e.Proposal.Kind != "" || len(e.Proposal.Witness) == 0 {
			continue
		}
		if err := ctx.Err(); err != nil {
			return res, err
		}

		res.Checked++
		missing, err := missingWitness(ctx, graph, e.Proposal.Witness)
		if err != nil {
			return res, err
		}
		if missing == "" {
			continue
		}

		if _, err := r.RetractOwnership(ctx, e.Outcome.EdgeID); err != nil {
			return res, fmt.Errorf("retract %s: %w", id, err)
		}
		if err := j.RecordOwnership(OwnershipOutcome{ProposalID: id, Status: ProposalRetracted,
			Reviewer: RecheckReviewer, EdgeID: e.Outcome.EdgeID}); err != nil {
			return res, err
		}

		res.Retracted = append(res.Retracted, e.Proposal)
	}

	return res, nil
}

// missingWitness returns the first evidence relationship that no longer
// exists, or "" when all do. A relationship that cannot be confirmed
// because its source has too many edges to read counts as present.
func missingWitness(ctx context.Context, graph Graph, witness []WitnessEdge) (string, error) {
	for _, w := range witness {
		if w.FromID == "" || w.ToID == "" || w.Label == "" {
			continue
		}

		var edges []Relation
		var more bool
		var err error
		if b, ok := graph.(BoundedGraph); ok {
			edges, more, err = b.EdgesLimited(ctx, w.FromID, "out", w.Label, time.Time{}, MaxEdgeRead)
		} else {
			edges, err = graph.Edges(ctx, w.FromID, "out", w.Label, time.Time{})
		}
		if err != nil {
			if _, gerr := graph.GetAsset(ctx, w.FromID); gerr != nil {
				// The source asset is gone.
				return fmt.Sprintf("%s %s", w.FromType, w.From), nil
			}
			return "", err
		}

		found := false
		for _, e := range edges {
			if e.ToID == w.ToID {
				found = true
				break
			}
		}
		if !found && !more {
			return fmt.Sprintf("%s %s --%s--> %s %s", w.FromType, w.From, w.Label, w.ToType, w.To), nil
		}
	}

	return "", nil
}

// redecidable reports whether a proposal's latest outcome still lets
// automatic attribution act on it: pending, or retracted by a re-check.
func redecidable(e *OwnershipEntry) bool {
	return e.Status == ProposalPending ||
		(e.Status == ProposalRetracted && e.Outcome != nil && e.Outcome.Reviewer == RecheckReviewer)
}
