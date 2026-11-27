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

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

func isPersonNamedProposal(id string) bool {
	return strings.HasPrefix(id, lens.PersonNamedPrefix)
}

// listPersonNamed finds organizations recorded under a person's name,
// prints them and records them in the journal as removal proposals.
// Nothing in the Asset Database changes.
func listPersonNamed(ctx context.Context, graph graph.Graph, j *review.Journal, format string, explicit bool,
	out, errout io.Writer) error {
	r, err := lens.FindPersonNamedOrganizations(ctx, graph)
	if err != nil {
		return err
	}
	if j != nil {
		added, err := j.SubmitPersonNamed(r.Candidates)
		if err != nil {
			return fmt.Errorf("record person-named organizations: %w", err)
		}

		_, _ = fmt.Fprintf(errout, "%d new removal proposal(s) recorded in %s; review with `amass review proposals`\n",
			len(added), j.Name())
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatPersonNamedReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("person-named format %q: use text or json", format)
}

func pendingPersonNamed(j *review.Journal, id, reviewer string) (lens.PersonNamedOrg, error) {
	if id == "" || reviewer == "" {
		return lens.PersonNamedOrg{}, errors.New("-proposal and -reviewer required")
	}

	state, err := j.PersonNamedState()
	if err != nil {
		return lens.PersonNamedOrg{}, err
	}

	e, ok := state[id]
	if !ok {
		return lens.PersonNamedOrg{}, fmt.Errorf("no person-named organization proposal %s in the journal", id)
	}
	if e.Status != review.ProposalPending {
		return lens.PersonNamedOrg{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}

	return e.Proposal, nil
}

func rejectPersonNamed(j *review.Journal, id, reviewer string, out io.Writer) error {
	if _, err := pendingPersonNamed(j, id, reviewer); err != nil {
		return err
	}
	if err := j.RecordPersonNamed(review.PersonNamedOutcome{ProposalID: id, Status: review.ProposalRejected,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; the organization was kept.\n", id)
	return err
}

func approvePersonNamed(ctx context.Context, r review.EntityRemover, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	p, err := pendingPersonNamed(j, id, reviewer)
	if err != nil {
		return err
	}

	rec, err := review.ApplyPersonNamedRemoval(ctx, r, j, p, reviewer)
	if err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Removed organization %q [%s] and its %d relationship(s); the person %q [%s] is kept. "+
		"Undo with `amass review retract -proposal %s`.\n", p.Organization, p.OrgID, len(rec.Edges), p.Person,
		p.PersonID, id)
	return err
}

func retractPersonNamed(ctx context.Context, r review.EntityRemover, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	state, err := j.PersonNamedState()
	if err != nil {
		return err
	}

	e, ok := state[id]
	if !ok {
		return fmt.Errorf("no person-named organization proposal %s in the journal", id)
	}
	if e.Status != review.ProposalApplied || e.Outcome == nil || e.Outcome.Record == nil {
		return fmt.Errorf("proposal %s is %s, not applied", id, e.Status)
	}

	restored, err := r.RestoreEntity(ctx, *e.Outcome.Record)
	if err != nil {
		return fmt.Errorf("restore organization for %s: %w", id, err)
	}
	if err := j.RecordPersonNamed(review.PersonNamedOutcome{ProposalID: id, Status: review.ProposalRetracted,
		Reviewer: reviewer, RestoredID: restored}); err != nil {
		return err
	}

	_, err = fmt.Fprintf(out, "Undid %s: restored organization %q as [%s].\n", id, e.Proposal.Organization, restored)
	return err
}
