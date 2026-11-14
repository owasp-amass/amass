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
	"github.com/owasp-amass/amass/v5/internal/review"
)

// recordGapProposals submits an investigation's ownership proposals to the
// journal, when one is set, and reports how many were new.
func recordGapProposals(journalPath string, result ai.Investigation, errout io.Writer) error {
	if journalPath == "" || result.GapReport == nil {
		return nil
	}

	added, err := (&review.Journal{Path: journalPath}).SubmitOwnership(review.OwnershipProposals(*result.GapReport))
	if err != nil {
		return fmt.Errorf("record ownership proposals: %w", err)
	}

	_, err = fmt.Fprintf(errout, "%d new ownership proposal(s) recorded in %s; review with `amass review proposals -journal %s`\n",
		len(added), journalPath, journalPath)
	return err
}

// trainAttribution trains the ownership model from the journal's review
// decisions and writes it where automatic attribution loads it.
func trainAttribution(journalPath, output string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	entries, err := (&review.Journal{Path: journalPath}).OwnershipEntries()
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

	j := &review.Journal{Path: journalPath}
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
		case id == "" && (e.Status != review.ProposalPending || (e.Advice != nil && e.Advice.Verified)):
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
		if _, err := fmt.Fprintln(out, review.FormatOwnershipEntries([]review.OwnershipEntry{e})+"\n"); err != nil {
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
