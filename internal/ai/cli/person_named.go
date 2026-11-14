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

func isPersonNamedProposal(id string) bool {
	return strings.HasPrefix(id, ai.PersonNamedPrefix)
}

// listPersonNamed finds organizations recorded under a person's name,
// prints them and records them in the journal as removal proposals.
// Nothing in the Asset Database changes.
func listPersonNamed(ctx context.Context, graph ai.Graph, journalPath, format string, explicit bool,
	out, errout io.Writer) error {
	r, err := ai.FindPersonNamedOrganizations(ctx, graph)
	if err != nil {
		return err
	}
	if journalPath != "" {
		added, err := (&ai.Journal{Path: journalPath}).SubmitPersonNamed(r.Candidates)
		if err != nil {
			return fmt.Errorf("record person-named organizations: %w", err)
		}

		_, _ = fmt.Fprintf(errout, "%d new removal proposal(s) recorded in %s; review with `amass review proposals`\n",
			len(added), journalPath)
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, ai.FormatPersonNamedReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("person-named format %q: use text or json", format)
}

func pendingPersonNamed(j *ai.Journal, id, reviewer string) (ai.PersonNamedOrg, error) {
	if id == "" || reviewer == "" {
		return ai.PersonNamedOrg{}, errors.New("-proposal and -reviewer required")
	}

	state, err := j.PersonNamedState()
	if err != nil {
		return ai.PersonNamedOrg{}, err
	}

	e, ok := state[id]
	if !ok {
		return ai.PersonNamedOrg{}, fmt.Errorf("no person-named organization proposal %s in the journal", id)
	}
	if e.Status != ai.ProposalPending {
		return ai.PersonNamedOrg{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}

	return e.Proposal, nil
}

func rejectPersonNamed(journalPath, id, reviewer string, out io.Writer) error {
	j := &ai.Journal{Path: journalPath}
	if _, err := pendingPersonNamed(j, id, reviewer); err != nil {
		return err
	}
	if err := j.RecordPersonNamed(ai.PersonNamedOutcome{ProposalID: id, Status: ai.ProposalRejected,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; the organization was kept.\n", id)
	return err
}

func approvePersonNamed(ctx context.Context, r ai.OrganizationRemover, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &ai.Journal{Path: journalPath}
	p, err := pendingPersonNamed(j, id, reviewer)
	if err != nil {
		return err
	}

	rec, err := ai.ApplyPersonNamedRemoval(ctx, r, j, p, reviewer)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Removed organization %q [%s] and its %d relationship(s); the person %q [%s] is kept. "+
		"Undo with `amass review retract -proposal %s`.\n", p.Organization, p.OrgID, len(rec.Edges), p.Person,
		p.PersonID, id)
	return err
}

func retractPersonNamed(ctx context.Context, r ai.OrganizationRemover, journalPath, id, reviewer string,
	out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	j := &ai.Journal{Path: journalPath}
	state, err := j.PersonNamedState()
	if err != nil {
		return err
	}

	e, ok := state[id]
	if !ok {
		return fmt.Errorf("no person-named organization proposal %s in the journal", id)
	}
	if e.Status != ai.ProposalApplied || e.Outcome == nil || e.Outcome.Record == nil {
		return fmt.Errorf("proposal %s is %s, not applied", id, e.Status)
	}

	restored, err := r.RestoreOrganization(ctx, *e.Outcome.Record)
	if err != nil {
		return fmt.Errorf("restore organization for %s: %w", id, err)
	}
	if err := j.RecordPersonNamed(ai.PersonNamedOutcome{ProposalID: id, Status: ai.ProposalRetracted,
		Reviewer: reviewer, RestoredID: restored}); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Undid %s: restored organization %q as [%s].\n", id, e.Proposal.Organization, restored)
	return err
}
