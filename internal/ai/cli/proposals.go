// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// recordGapProposals submits an investigation's ownership proposals to the
// journal, when one is set, and reports how many were new.
func recordGapProposals(journalPath string, result ai.Investigation, errout io.Writer) error {
	if journalPath == "" || result.GapReport == nil {
		return nil
	}

	added, err := (&ai.Journal{Path: journalPath}).SubmitOwnership(ai.OwnershipProposals(*result.GapReport))
	if err != nil {
		return fmt.Errorf("record ownership proposals: %w", err)
	}

	_, err = fmt.Fprintf(errout, "%d new ownership proposal(s) recorded in %s; review with `amass ai -journal %s proposals`\n",
		len(added), journalPath, journalPath)
	return err
}

// listProposals prints the journal's ownership proposals.
func listProposals(journalPath, format string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	entries, err := (&ai.Journal{Path: journalPath}).OwnershipEntries()
	if err != nil {
		return err
	}
	if format == "json" {
		return writeJSON(out, entries)
	}

	_, err = fmt.Fprintln(out, ai.FormatOwnershipEntries(entries))
	return err
}

// pendingProposal finds a proposal that has not been reviewed.
func pendingProposal(j *ai.Journal, id, reviewer string) (ai.OwnershipProposal, error) {
	if id == "" || reviewer == "" {
		return ai.OwnershipProposal{}, errors.New("-proposal and -reviewer required")
	}

	state, err := j.OwnershipState()
	if err != nil {
		return ai.OwnershipProposal{}, err
	}

	e, ok := state[id]
	if !ok {
		return ai.OwnershipProposal{}, fmt.Errorf("no ownership proposal %s in the journal", id)
	}
	if e.Status != ai.ProposalPending {
		return ai.OwnershipProposal{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}

	return e.Proposal, nil
}

// rejectProposal records a reviewer's rejection; nothing is written to the
// Asset Database.
func rejectProposal(journalPath, id, reviewer string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &ai.Journal{Path: journalPath}
	if _, err := pendingProposal(j, id, reviewer); err != nil {
		return err
	}
	if err := j.RecordOwnership(ai.OwnershipOutcome{ProposalID: id, Status: ai.ProposalRejected,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; nothing was written.\n", id)
	return err
}

// approveProposal writes a pending proposal's relationship with the
// amass-ai source and the proposal's score as confidence, then records the
// edge in the journal.
func approveProposal(ctx context.Context, w ai.OwnershipWriter, journalPath, id, reviewer string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &ai.Journal{Path: journalPath}
	p, err := pendingProposal(j, id, reviewer)
	if err != nil {
		return err
	}

	confidence := ai.ProposalConfidence(p)
	edgeID, existed, err := w.ApplyOwnership(ctx, p.Edge, confidence)
	if err != nil {
		return fmt.Errorf("write %s: %w", p.Edge, err)
	}
	if err := j.RecordOwnership(ai.OwnershipOutcome{ProposalID: id, Status: ai.ProposalApplied,
		Reviewer: reviewer, EdgeID: edgeID}); err != nil {
		return fmt.Errorf("edge %s was written but the journal was not updated: %w", edgeID, err)
	}
	if existed {
		_, err = fmt.Fprintf(out, "Already recorded as edge %s: %s\n", edgeID, p.Edge)
		return err
	}

	_, err = fmt.Fprintf(out, "Wrote edge %s: %s (source %s, confidence %d)\n", edgeID, p.Edge,
		ai.InferenceSource, confidence)
	return err
}

// ownershipRetractor removes a relationship written from a proposal.
type ownershipRetractor interface {
	RetractOwnership(ctx context.Context, edgeID string) (bool, error)
}

// retractProposal removes an applied proposal's amass-ai relationship and
// records the retraction, so automatic attribution never writes it again.
func retractProposal(ctx context.Context, r ownershipRetractor, journalPath, id, reviewer string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	j := &ai.Journal{Path: journalPath}
	state, err := j.OwnershipState()
	if err != nil {
		return err
	}

	e, ok := state[id]
	if !ok {
		return fmt.Errorf("no ownership proposal %s in the journal", id)
	}
	if e.Status != ai.ProposalApplied || e.Outcome == nil || e.Outcome.EdgeID == "" {
		return fmt.Errorf("proposal %s is %s, not applied", id, e.Status)
	}

	edgeID := e.Outcome.EdgeID
	removed, err := r.RetractOwnership(ctx, edgeID)
	if err != nil {
		return fmt.Errorf("retract edge %s: %w", edgeID, err)
	}
	if err := j.RecordOwnership(ai.OwnershipOutcome{ProposalID: id, Status: ai.ProposalRetracted,
		Reviewer: reviewer, EdgeID: edgeID}); err != nil {
		return err
	}
	if removed {
		_, err = fmt.Fprintf(out, "Removed edge %s: %s\n", edgeID, e.Proposal.Edge)
	} else {
		_, err = fmt.Fprintf(out, "Removed the %s source from edge %s; other sources also record it\n",
			ai.InferenceSource, edgeID)
	}

	return err
}
