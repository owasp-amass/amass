// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"fmt"
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
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
func RecheckAttributions(ctx context.Context, graph graph.Graph, r OwnershipRetractor, j *Journal) (RecheckResult, error) {
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
// exists, or "" when all do. The source's edges with the evidence label are
// read a page at a time until the relationship is found or none are left,
// up to lensMaxPerLabel edges; a relationship that still cannot be
// confirmed counts as present, so evidence is never declared gone unread.
// A matched value (two assets found to share a value, such as an email
// domain) is a comparison, not a stored relationship: it is gone only when
// one of its two assets is.
func missingWitness(ctx context.Context, g graph.Graph, witness []graph.WitnessEdge) (string, error) {
	for _, w := range witness {
		if w.FromID == "" || w.ToID == "" || w.Label == "" {
			continue
		}
		if w.RelationType == lens.MatchedValueRelation {
			for _, end := range []struct{ id, typ, name string }{{w.FromID, w.FromType, w.From}, {w.ToID, w.ToType, w.To}} {
				if _, err := g.GetAsset(ctx, end.id); err != nil {
					return fmt.Sprintf("%s %s", end.typ, end.name), nil
				}
			}
			continue
		}

		found, complete, err := findEdge(ctx, g, w.FromID, w.Label, w.ToID)
		if err != nil {
			if _, gerr := g.GetAsset(ctx, w.FromID); gerr != nil {
				// The source asset is gone.
				return fmt.Sprintf("%s %s", w.FromType, w.From), nil
			}
			return "", err
		}
		if !found && complete {
			return fmt.Sprintf("%s %s --%s--> %s %s", w.FromType, w.From, w.Label, w.ToType, w.To), nil
		}
	}

	return "", nil
}

// findEdge looks for an out edge from one asset to another with a label.
// complete reports that every such edge of the source was read.
func findEdge(ctx context.Context, g graph.Graph, from, label, to string) (bool, bool, error) {
	pager, ok := g.(graph.PagedGraph)
	if !ok {
		var edges []graph.Relation
		var more bool
		var err error
		if b, ok := g.(graph.BoundedGraph); ok {
			edges, more, err = b.EdgesLimited(ctx, from, "out", label, time.Time{}, graph.MaxEdgeRead)
		} else {
			edges, err = g.Edges(ctx, from, "out", label, time.Time{})
		}
		if err != nil {
			return false, false, err
		}
		for _, e := range edges {
			if e.ToID == to {
				return true, true, nil
			}
		}
		return false, !more, nil
	}

	cursor := ""
	for {
		edges, next, err := pager.EdgesPage(ctx, from, "out", label, time.Time{}, cursor, graph.MaxEdgeRead)
		if err != nil {
			return false, false, err
		}
		for _, e := range edges {
			if e.ToID == to {
				return true, true, nil
			}
		}
		if next == "" {
			return false, true, nil
		}

		cursor = next
	}
}

// Redecidable reports whether a proposal's latest outcome still lets
// automatic attribution act on it: pending, or retracted by a re-check.
func Redecidable(e *OwnershipEntry) bool {
	return e.Status == ProposalPending ||
		(e.Status == ProposalRetracted && e.Outcome != nil &&
			(e.Outcome.Reviewer == RecheckReviewer || e.Outcome.Reviewer == SupersededReviewer))
}
