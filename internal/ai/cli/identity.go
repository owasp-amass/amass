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

func isIdentityProposal(id string) bool {
	return strings.HasPrefix(id, ai.IdentityPrefix)
}

// listIdentityConflicts checks the stored organizations' legal identities
// against their evidence, prints the contradictions and records them in
// the journal as correction proposals. Nothing in the Asset Database
// changes.
func listIdentityConflicts(ctx context.Context, graph ai.Graph, journalPath, format string, explicit bool,
	out, errout io.Writer) error {
	r, err := ai.FindIdentityConflicts(ctx, graph)
	if err != nil {
		return err
	}
	if journalPath != "" {
		added, err := (&ai.Journal{Path: journalPath}).SubmitIdentityConflicts(r.Conflicts)
		if err != nil {
			return fmt.Errorf("record identity corrections: %w", err)
		}

		_, _ = fmt.Fprintf(errout, "%d new identity correction(s) recorded in %s; review with `amass ai proposals`\n",
			len(added), journalPath)
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, ai.FormatIdentityReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("identity-conflicts format %q: use text or json", format)
}

func pendingIdentity(j *ai.Journal, id, reviewer string) (ai.IdentityConflict, error) {
	if id == "" || reviewer == "" {
		return ai.IdentityConflict{}, errors.New("-proposal and -reviewer required")
	}

	state, err := j.IdentityState()
	if err != nil {
		return ai.IdentityConflict{}, err
	}

	e, ok := state[id]
	if !ok {
		return ai.IdentityConflict{}, fmt.Errorf("no identity correction %s in the journal", id)
	}
	if e.Status != ai.ProposalPending {
		return ai.IdentityConflict{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}

	return e.Proposal, nil
}

func rejectIdentity(journalPath, id, reviewer string, out io.Writer) error {
	j := &ai.Journal{Path: journalPath}
	if _, err := pendingIdentity(j, id, reviewer); err != nil {
		return err
	}
	if err := j.RecordIdentity(ai.IdentityOutcome{ProposalID: id, Status: ai.ProposalRejected,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; the legal identity was kept.\n", id)
	return err
}

func approveIdentity(ctx context.Context, c ai.IdentityCorrector, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &ai.Journal{Path: journalPath}
	p, err := pendingIdentity(j, id, reviewer)
	if err != nil {
		return err
	}

	rec, err := ai.ApplyIdentityCorrection(ctx, c, j, p, reviewer)
	if err != nil {
		return err
	}

	deleted := 0
	for _, e := range rec.Edges {
		if e.Deleted {
			deleted++
		}
	}

	_, err = fmt.Fprintf(out, "Removed legal identity %q (%s) from %s [%s]: %d relationship(s) deleted, %d kept "+
		"with their other sources. Undo with -proposal %s retract.\n", p.LegalName, p.Jurisdiction, p.Organization,
		p.OrgID, deleted, len(rec.Edges)-deleted, id)
	return err
}

func retractIdentity(ctx context.Context, c ai.IdentityCorrector, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	j := &ai.Journal{Path: journalPath}
	state, err := j.IdentityState()
	if err != nil {
		return err
	}

	e, ok := state[id]
	if !ok {
		return fmt.Errorf("no identity correction %s in the journal", id)
	}
	if e.Status != ai.ProposalApplied || e.Outcome == nil || e.Outcome.Record == nil {
		return fmt.Errorf("proposal %s is %s, not applied", id, e.Status)
	}
	if err := c.UndoIdentityCorrection(ctx, *e.Outcome.Record); err != nil {
		return fmt.Errorf("undo correction %s: %w", id, err)
	}
	if err := j.RecordIdentity(ai.IdentityOutcome{ProposalID: id, Status: ai.ProposalRetracted,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Undid correction %s: %s [%s] has its legal identity %q (%s) again.\n", id,
		e.Proposal.Organization, e.Proposal.OrgID, e.Proposal.LegalName, e.Proposal.Jurisdiction)
	return err
}
