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

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// isMergeProposal reports whether id names a merge proposal rather than an
// ownership proposal.
func isMergeProposal(id string) bool {
	return strings.HasPrefix(id, ai.DuplicatePrefix)
}

// pendingMerge finds a merge proposal that has not been reviewed.
func pendingMerge(j *ai.Journal, id, reviewer string) (ai.DuplicateProposal, error) {
	if id == "" || reviewer == "" {
		return ai.DuplicateProposal{}, errors.New("-proposal and -reviewer required")
	}

	state, err := j.DuplicateState()
	if err != nil {
		return ai.DuplicateProposal{}, err
	}

	e, ok := state[id]
	if !ok {
		return ai.DuplicateProposal{}, fmt.Errorf("no merge proposal %s in the journal", id)
	}
	if e.Status != ai.ProposalPending {
		return ai.DuplicateProposal{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}

	return e.Proposal, nil
}

// rejectMerge records a reviewer's rejection; nothing is written to the
// Asset Database.
func rejectMerge(journalPath, id, reviewer string, out io.Writer) error {
	j := &ai.Journal{Path: journalPath}
	if _, err := pendingMerge(j, id, reviewer); err != nil {
		return err
	}
	if err := j.RecordDuplicate(ai.DuplicateOutcome{ProposalID: id, Status: ai.ProposalRejected,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; nothing was merged.\n", id)
	return err
}

// approveMerge merges a pending proposal's duplicate into its survivor and
// records everything the merge changed in the journal.
func approveMerge(ctx context.Context, m ai.OrganizationMerger, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &ai.Journal{Path: journalPath}
	p, err := pendingMerge(j, id, reviewer)
	if err != nil {
		return err
	}

	rec, err := ai.ApplyMerge(ctx, m, j, p, reviewer)
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
		"Undo with -proposal %s retract.\n", p.Duplicate, p.DuplicateID, p.Survivor, p.SurvivorID, moved,
		ai.InferenceSource, ai.MergeConfidence(p), id)
	return err
}

// retractMerge undoes an applied merge: the duplicate is restored with its
// relationships, and the survivor loses only what the merge added.
func retractMerge(ctx context.Context, m ai.OrganizationMerger, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	j := &ai.Journal{Path: journalPath}
	state, err := j.DuplicateState()
	if err != nil {
		return err
	}

	e, ok := state[id]
	if !ok {
		return fmt.Errorf("no merge proposal %s in the journal", id)
	}
	if e.Status != ai.ProposalApplied || e.Outcome == nil || e.Outcome.Merge == nil {
		return fmt.Errorf("proposal %s is %s, not applied", id, e.Status)
	}

	res, err := m.UnmergeOrganizations(ctx, *e.Outcome.Merge)
	if err != nil {
		return fmt.Errorf("undo merge %s: %w", id, err)
	}
	if err := j.RecordDuplicate(ai.DuplicateOutcome{ProposalID: id, Status: ai.ProposalRetracted,
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
