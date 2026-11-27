// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// isMergeProposal reports whether id names a merge proposal — an organization
// merge or a person merge — rather than an ownership proposal.
func isMergeProposal(id string) bool {
	return strings.HasPrefix(id, review.DuplicatePrefix) || review.IsPersonMerge(id)
}

// pendingMerge finds a merge proposal that has not been reviewed.
func pendingMerge(j *review.Journal, id, reviewer string) (review.DuplicateProposal, error) {
	if id == "" || reviewer == "" {
		return review.DuplicateProposal{}, errors.New("-proposal and -reviewer required")
	}

	state, err := j.DuplicateState()
	if err != nil {
		return review.DuplicateProposal{}, err
	}

	e, ok := state[id]
	if !ok {
		return review.DuplicateProposal{}, fmt.Errorf("no merge proposal %s in the journal", id)
	}
	if e.Status != review.ProposalPending {
		return review.DuplicateProposal{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}

	return e.Proposal, nil
}

// rejectMerge records a reviewer's rejection; nothing is written to the
// Asset Database.
func rejectMerge(j *review.Journal, id, reviewer string, out io.Writer) error {
	if _, err := pendingMerge(j, id, reviewer); err != nil {
		return err
	}
	if err := j.RecordDuplicate(review.DuplicateOutcome{ProposalID: id, Status: review.ProposalRejected,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; nothing was merged.\n", id)
	return err
}

// approveMerge merges a pending proposal's duplicate into its survivor and
// records everything the merge changed in the journal. The proposal ID says
// whether it is an organization merge or a person merge.
func approveMerge(ctx context.Context, m review.Merger, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	p, err := pendingMerge(j, id, reviewer)
	if err != nil {
		return err
	}

	var rec review.MergeRecord
	if review.IsPersonMerge(id) {
		rec, err = review.ApplyPersonMerge(ctx, m, j, p, reviewer)
	} else {
		rec, err = review.ApplyMerge(ctx, m, j, p, reviewer)
	}
	if err != nil {
		return err
	}

	moved := 0
	for _, e := range rec.Edges {
		if e.Skipped == "" {
			moved++
		}
	}

	_, err = fmt.Fprintf(out, "Merged %s [%s] into %s [%s]: %d relationship(s) moved (source %s, confidence %d). "+
		"Undo with `amass review retract -proposal %s`.\n", p.Duplicate, p.DuplicateID, p.Survivor, p.SurvivorID, moved,
		review.InferenceSource, review.MergeConfidence(p), id)
	return err
}

// retractMerge undoes an applied merge: the duplicate is restored with its
// relationships, and the survivor loses only what the merge added.
func retractMerge(ctx context.Context, m review.OrganizationMerger, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	state, err := j.DuplicateState()
	if err != nil {
		return err
	}

	e, ok := state[id]
	if !ok {
		return fmt.Errorf("no merge proposal %s in the journal", id)
	}
	if e.Status != review.ProposalApplied || e.Outcome == nil || e.Outcome.Merge == nil {
		return fmt.Errorf("proposal %s is %s, not applied", id, e.Status)
	}

	res, err := m.UnmergeOrganizations(ctx, *e.Outcome.Merge)
	if err != nil {
		return fmt.Errorf("undo merge %s: %w", id, err)
	}
	if err := j.RecordDuplicate(review.DuplicateOutcome{ProposalID: id, Status: review.ProposalRetracted,
		Reviewer: reviewer, RestoredID: res.RestoredID, KeptFields: res.KeptFields}); err != nil {
		return fmt.Errorf("%s was restored as %s but the journal was not updated: %w", e.Proposal.Duplicate,
			res.RestoredID, err)
	}

	_, err = fmt.Fprintf(out, "Undid merge %s: %s restored as [%s]; %s [%s] no longer has what the merge added.\n",
		id, e.Proposal.Duplicate, res.RestoredID, e.Proposal.Survivor, e.Proposal.SurvivorID)
	if err == nil && len(res.KeptFields) > 0 {
		_, err = fmt.Fprintf(out, "It keeps %s filled by the merge: changed since, or not clearable here.\n",
			strings.Join(res.KeptFields, ", "))
	}
	return err
}

// keepMergedNames gives merges applied before merges kept every name the
// names their duplicates had (review.Journal.KeepMergedNames).
func keepMergedNames(ctx context.Context, k review.MergeNameKeeper, j *review.Journal, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	kept, gone, err := j.KeepMergedNames(ctx, k)
	msg := fmt.Sprintf("Kept the names of %d earlier merges; undoing a merge removes them.\n", kept)
	if gone > 0 {
		msg += fmt.Sprintf("Skipped %d whose merged record is no longer in the database.\n", gone)
	}
	if _, werr := fmt.Fprint(out, msg); err == nil {
		err = werr
	}
	return err
}
