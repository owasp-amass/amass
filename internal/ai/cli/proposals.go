// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// ownershipWriter writes an approved ownership proposal to the Asset
// Database and returns the edge ID and whether it was already stored.
type ownershipWriter interface {
	ApplyOwnership(ctx context.Context, e ai.ProposedEdge, confidence int) (string, bool, error)
}

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
func approveProposal(ctx context.Context, w ownershipWriter, journalPath, id, reviewer string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &ai.Journal{Path: journalPath}
	p, err := pendingProposal(j, id, reviewer)
	if err != nil {
		return err
	}

	confidence := int(math.Round(math.Max(0, math.Min(1, p.Score)) * 100))
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
