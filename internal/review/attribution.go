// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// OwnershipWriter writes an approved ownership proposal to the Asset
// Database and returns the edge ID and whether it was already stored.
type OwnershipWriter interface {
	ApplyOwnership(ctx context.Context, e lens.ProposedEdge, confidence int) (string, bool, error)
}

// ProposalConfidence is the source confidence written for a proposal: the
// ownership model's probability when a model decided it, otherwise the rule
// score, as a percentage.
func ProposalConfidence(p OwnershipProposal) int {
	score := p.Score
	if p.ModelID != "" {
		score = p.ModelScore
	}

	return int(math.Round(math.Max(0, math.Min(1, score)) * 100))
}

// OwnershipScorer is a trained model that decides automatic attribution in
// place of the rules.
type OwnershipScorer interface {
	// ModelName identifies the model in the journal.
	ModelName() string
	// Probability is how likely p's owner is to own p's asset.
	Probability(p OwnershipProposal) (float64, error)
	// Threshold is the probability at which a proposal qualifies.
	Threshold() float64
}

// AttributionPolicy is how automatic attribution decides.
type AttributionPolicy struct {
	// Mode is "auto" (write what qualifies) or "journal" (write nothing).
	Mode string
	// Model, when set, decides in place of the rules: a proposal qualifies
	// when its probability of ownership reaches the model's review
	// threshold. Without one, a proposal qualifies when the rules decide
	// propose.
	Model OwnershipScorer
	// Anchors, when set, are the registered domains an enumeration was asked
	// about. Only an organization whose footprint includes one of them (or
	// a domain above or below one) is attributed, so organizations an
	// enumeration only touched, such as certificate authorities and other
	// vendors pulled into scope, are never attribution roots.
	Anchors []string
}

// AttributionResult is one automatic attribution pass for an organization.
type AttributionResult struct {
	Report lens.OwnershipGapReport
	// Applied are the proposals written in this pass, with the assets each
	// brought under the organization.
	Applied []AppliedOwnership
	// Queued are proposals left in the journal for review.
	Queued []OwnershipProposal
	// Unanchored reports an organization whose footprint holds none of the
	// policy's anchor domains; nothing was proposed for it.
	Unanchored bool
	// Superseded are proposals not recorded because the organization is the
	// duplicate side of a pending merge whose survivor already proposes the
	// same asset.
	Superseded []OwnershipProposal
}

// AppliedOwnership is a proposal written to the Asset Database.
type AppliedOwnership struct {
	Proposal OwnershipProposal
	EdgeID   string
	Existed  bool
	// Gains are the assets the relationship brought under the owner.
	Gains []graph.Asset
}

// AttributeOwnership finds the ownership gaps of org and acts on them without
// a person's review: in auto mode, proposals that qualify under policy are
// written with w; everything else attachable, and everything in journal
// mode, is left in the journal for review. A proposal with a recorded decision is never
// acted on again, so a rejected or retracted proposal is not rewritten; one
// still pending is written once its evidence reaches propose.
// Every write is recorded in the journal with AutomaticReviewer.
func AttributeOwnership(ctx context.Context, g graph.Graph, schema graph.SchemaCatalog, org graph.Asset, w OwnershipWriter,
	j *Journal, policy AttributionPolicy) (AttributionResult, error) {
	mode := policy.Mode
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

	report, err := lens.SearchOwnershipGaps(ctx, g, schema, org)
	res.Report = report
	if err != nil {
		return res, err
	}
	if !anchored(report.Domains, policy.Anchors) {
		res.Unanchored = true
		return res, nil
	}

	state, err := j.OwnershipState()
	if err != nil {
		return res, err
	}

	merges, err := pendingMerges(j)
	if err != nil {
		return res, err
	}

	gains := map[string][]graph.Asset{}
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
		if known && !Redecidable(e) {
			// Applied, rejected or retracted by a person: a decision was
			// made. A re-check's retraction only says the evidence was gone.
			continue
		}
		// Two records of one organization awaiting a merge would each be
		// proposed as owning the same assets; keep the merge survivor's
		// proposal and set the duplicate's aside.
		if !known && merges.survivorProposes(org.ID, p.AssetID, state) {
			res.Superseded = append(res.Superseded, p)
			continue
		}
		if err := merges.supersedeDuplicates(j, org.ID, p.AssetID, state); err != nil {
			return res, err
		}

		qualifies := p.Decision == lens.GapPropose
		if policy.Model != nil {
			prob, err := policy.Model.Probability(p)
			if err != nil {
				return res, err
			}

			p.ModelID, p.ModelScore = policy.Model.ModelName(), prob
			qualifies = prob >= policy.Model.Threshold()
		}
		if !known {
			if _, err := j.SubmitOwnership([]OwnershipProposal{p}); err != nil {
				return res, err
			}
		}
		if mode != "auto" || !qualifies {
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

// anchored reports whether an owner's domains include an anchor domain, or a
// domain above or below one. Without anchors every owner is anchored.
func anchored(domains, anchors []string) bool {
	if len(anchors) == 0 {
		return true
	}
	for _, d := range domains {
		for _, a := range anchors {
			if lens.HostWithin(a, d) || lens.HostWithin(d, a) {
				return true
			}
		}
	}

	return false
}

// SupersededReviewer is the reviewer recorded when a pending ownership
// proposal is set aside because the organization it names is the duplicate
// side of a pending merge and the survivor proposes the same asset. Like a
// re-check's retraction it is not a decision: if the merge is rejected, the
// duplicate's next attribution pass may propose the asset again.
const SupersededReviewer = "amass-ai (superseded by merge)"

// mergePairs are the pending merges, by survivor and by duplicate.
type mergePairs struct {
	survivorsOf  map[string][]string // duplicate ID -> survivor IDs
	duplicatesOf map[string][]string // survivor ID -> duplicate IDs
}

func pendingMerges(j *Journal) (mergePairs, error) {
	m := mergePairs{survivorsOf: map[string][]string{}, duplicatesOf: map[string][]string{}}
	entries, err := j.DuplicateEntries()
	if err != nil {
		return m, err
	}

	for _, e := range entries {
		if e.Status != ProposalPending || e.Proposal.SurvivorID == "" || e.Proposal.DuplicateID == "" {
			continue
		}

		s, d := e.Proposal.SurvivorID, e.Proposal.DuplicateID
		m.survivorsOf[d] = append(m.survivorsOf[d], s)
		m.duplicatesOf[s] = append(m.duplicatesOf[s], d)
	}

	return m, nil
}

// survivorProposes reports whether org is the duplicate side of a pending
// merge whose survivor already has a proposal (in any state) for asset.
func (m mergePairs) survivorProposes(org, asset string, state map[string]*OwnershipEntry) bool {
	survivors := m.survivorsOf[org]
	if len(survivors) == 0 || asset == "" {
		return false
	}

	for _, e := range state {
		if e.Proposal.AssetID == asset && slices.Contains(survivors, e.Proposal.OwnerID) {
			return true
		}
	}
	return false
}

// supersedeDuplicates sets aside the still-pending proposals for asset made
// for organizations that are the duplicate side of a pending merge into org,
// so the reviewer sees the survivor's proposal once.
func (m mergePairs) supersedeDuplicates(j *Journal, org, asset string, state map[string]*OwnershipEntry) error {
	dups := m.duplicatesOf[org]
	if len(dups) == 0 || asset == "" {
		return nil
	}

	for id, e := range state {
		if e.Status != ProposalPending || e.Proposal.AssetID != asset || !slices.Contains(dups, e.Proposal.OwnerID) {
			continue
		}
		if err := j.RecordOwnership(OwnershipOutcome{ProposalID: id, Status: ProposalRetracted,
			Reviewer: SupersededReviewer}); err != nil {
			return err
		}

		e.Status = ProposalRetracted
	}
	return nil
}
