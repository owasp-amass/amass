// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

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

// trainAttribution trains the ownership model from the journal's review
// decisions and writes it where automatic attribution loads it.
func trainAttribution(journalPath, output string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	entries, err := (&ai.Journal{Path: journalPath}).OwnershipEntries()
	if err != nil {
		return err
	}

	rows, spec := ai.OwnershipTrainingSet(entries)
	model, metrics, err := ai.TrainOwnershipModel(rows, spec, "ownership-"+time.Now().UTC().Format("20060102-150405"))
	if err != nil {
		return fmt.Errorf("train from %d reviewed proposals: %w", len(rows), err)
	}
	if output == "" {
		output = ai.AttributionModelPath(journalPath)
	}

	data, err := json.MarshalIndent(model, "", "  ")
	if err != nil {
		return err
	}

	tmp := output + ".tmp"
	if err := os.WriteFile(tmp, append(data, '\n'), 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, output); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Trained %s from %d reviewed proposals (%d held out): accuracy %.2f, precision %.2f, "+
		"recall %.2f.\nAutomatic writes need a probability of %.2f. Saved to %s; the engine uses it from the next "+
		"enumeration.\n", model.ModelID, metrics.TrainingExamples+metrics.HoldoutExamples, metrics.HoldoutExamples,
		metrics.HoldoutAccuracy, metrics.HoldoutPotentialPrecision, metrics.HoldoutPotentialRecall,
		model.ReviewThreshold, output)
	return err
}

// reviewProposals asks the model for advice on pending proposals without
// verified advice (or on the one named), records it in the journal and
// prints it. Advice never approves, rejects or writes anything.
func reviewProposals(ctx context.Context, agent ai.Agent, model, journalPath, id string, limit int,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &ai.Journal{Path: journalPath}
	entries, err := j.OwnershipEntries()
	if err != nil {
		return err
	}

	reviewed := 0
	for _, e := range entries {
		if reviewed >= limit {
			break
		}

		switch {
		case id != "" && e.Proposal.ID != id:
			continue
		case id == "" && (e.Status != ai.ProposalPending || (e.Advice != nil && e.Advice.Verified)):
			continue
		}

		adv, err := agent.AdviseOwnership(ctx, e.Proposal, model)
		if err != nil {
			return fmt.Errorf("advise on %s: %w", e.Proposal.ID, err)
		}
		if err := j.RecordAdvice(adv); err != nil {
			return err
		}

		reviewed++
		e.Advice = &adv
		if _, err := fmt.Fprintln(out, ai.FormatOwnershipEntries([]ai.OwnershipEntry{e})+"\n"); err != nil {
			return err
		}
	}
	if reviewed == 0 {
		_, err = fmt.Fprintln(out, "No pending proposals need advice.")
		return err
	}

	_, err = fmt.Fprintf(out, "Advised on %d proposal(s). Advice is a recommendation only: approve or reject with "+
		"-proposal ID -reviewer NAME.\n", reviewed)
	return err
}

// listSignals prints the ownership signal catalog: each signal with what it
// finds, why it counts, its guards and when it can mislead. Text is the
// default; markdown is docs/ai/SIGNALS.md.
func listSignals(format string, explicit bool, out io.Writer) error {
	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, ai.SignalsText())
		return err
	case format == "markdown":
		_, err := fmt.Fprint(out, ai.SignalsMarkdown())
		return err
	case format == "json":
		return writeJSON(out, ai.OwnershipSignals())
	}

	return fmt.Errorf("signals format %q: use text, json or markdown", format)
}
