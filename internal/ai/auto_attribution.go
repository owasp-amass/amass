// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"fmt"
	"math"
)

// OwnershipWriter writes an approved ownership proposal to the Asset
// Database and returns the edge ID and whether it was already stored.
type OwnershipWriter interface {
	ApplyOwnership(ctx context.Context, e ProposedEdge, confidence int) (string, bool, error)
}

// ProposalConfidence is the source confidence written for a proposal: its
// score as a percentage.
func ProposalConfidence(p OwnershipProposal) int {
	return int(math.Round(math.Max(0, math.Min(1, p.Score)) * 100))
}

// AttributionResult is one automatic attribution pass for an organization.
type AttributionResult struct {
	Report OwnershipGapReport
	// Applied are the proposals written in this pass, with the assets each
	// brought under the organization.
	Applied []AppliedOwnership
	// Queued are proposals left in the journal for review.
	Queued []OwnershipProposal
}

// AppliedOwnership is a proposal written to the Asset Database.
type AppliedOwnership struct {
	Proposal OwnershipProposal
	EdgeID   string
	Existed  bool
	// Gains are the assets the relationship brought under the owner.
	Gains []Asset
}

// AttributeOwnership finds the ownership gaps of org and acts on them without
// a person's review: in auto mode, proposals decided propose are written with
// w; everything else attachable, and everything in journal mode, is left in
// the journal for review. A proposal with a recorded decision is never
// acted on again, so a rejected or retracted proposal is not rewritten; one
// still pending is written once its evidence reaches propose.
// Every write is recorded in the journal with AutomaticReviewer.
func AttributeOwnership(ctx context.Context, graph Graph, schema SchemaCatalog, org Asset, w OwnershipWriter,
	j *Journal, mode string) (AttributionResult, error) {
	var res AttributionResult
	if j == nil || j.Path == "" {
		// Without a journal, rejections and retractions could not be honored.
		return res, errors.New("automatic attribution requires a review journal")
	}
	if mode != "auto" && mode != "journal" {
		return res, fmt.Errorf("unsupported attribution mode %q", mode)
	}
	if mode == "auto" && w == nil {
		return res, errors.New("automatic attribution requires an ownership writer")
	}
	if org.Type != "Organization" {
		return res, fmt.Errorf("attribution starts from an Organization, not %s", org.Type)
	}

	report, err := searchOwnershipGaps(ctx, graph, schema, org)
	res.Report = report
	if err != nil {
		return res, err
	}

	state, err := j.OwnershipState()
	if err != nil {
		return res, err
	}

	gains := map[string][]Asset{}
	for _, c := range report.Candidates {
		if c.Attachment != nil {
			gains[ProposalID(*c.Attachment)] = c.GainAssets
		}
	}
	for _, p := range OwnershipProposals(report) {
		if err := ctx.Err(); err != nil {
			return res, err
		}
		e, known := state[p.ID]
		if known && e.Status != ProposalPending {
			// Applied, rejected or retracted: a decision was made.
			continue
		}
		if !known {
			if _, err := j.SubmitOwnership([]OwnershipProposal{p}); err != nil {
				return res, err
			}
		}
		if mode != "auto" || p.Decision != GapPropose {
			if !known {
				res.Queued = append(res.Queued, p)
			}

			continue
		}

		edgeID, existed, err := w.ApplyOwnership(ctx, p.Edge, ProposalConfidence(p))
		if err != nil {
			return res, fmt.Errorf("write %s: %w", p.Edge, err)
		}
		if err := j.RecordOwnership(OwnershipOutcome{ProposalID: p.ID, Status: ProposalApplied,
			Reviewer: AutomaticReviewer, EdgeID: edgeID}); err != nil {
			return res, err
		}

		res.Applied = append(res.Applied, AppliedOwnership{Proposal: p, EdgeID: edgeID, Existed: existed,
			Gains: gains[p.ID]})
	}

	return res, nil
}
