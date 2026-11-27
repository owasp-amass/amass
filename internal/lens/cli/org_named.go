// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// OrgNamedAdvice, when set, gives new organization-named person proposals
// the trained name-kind classifier's answer as advice before they are
// recorded. The amass command sets it to ai.OrgNamedAdvice: this package runs
// with no language model and does not import internal/ai.
var OrgNamedAdvice func(j *review.Journal, candidates []lens.OrgNamedPerson) error

// listOrgNamed finds people recorded under an organization's name, prints
// them and records them in the journal as conversion proposals. Nothing in
// the Asset Database changes.
func listOrgNamed(ctx context.Context, g graph.Graph, j *review.Journal, format string, explicit bool,
	out, errout io.Writer) error {
	r, err := lens.FindOrgNamedPersons(ctx, g)
	if err != nil {
		return err
	}
	if j != nil {
		// a new proposal records the name classifier's answer as advice
		if OrgNamedAdvice != nil {
			if err := OrgNamedAdvice(j, r.Candidates); err != nil {
				_, _ = fmt.Fprintf(errout, "no name classifier advice: %v\n", err)
			}
		}
		added, err := j.SubmitOrgNamed(r.Candidates)
		if err != nil {
			return fmt.Errorf("record organization-named people: %w", err)
		}
		_, _ = fmt.Fprintf(errout, "%d new conversion proposal(s) recorded in %s; review with `amass review proposals`\n",
			len(added), j.Name())
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatOrgNamedReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}
	return fmt.Errorf("org-named format %q: use text or json", format)
}

// approveOrgNamed converts a pending proposal's person into an
// organization.
func approveOrgNamed(ctx context.Context, w review.PersonConverter, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	rec, err := review.ApplyOrgNamed(ctx, w, j, id, reviewer)
	if err != nil {
		return err
	}

	verb := "Moved"
	if rec.OrgCreated {
		verb = "Created organization [" + rec.OrgID + "] and moved"
	} else {
		verb += " to organization [" + rec.OrgID + "]"
	}
	_, err = fmt.Fprintf(out, "%s %d relationship(s); the person [%s] was removed", verb, len(rec.AddedEdges),
		rec.Person.EntityID)
	if err == nil && len(rec.Dropped) > 0 {
		_, err = fmt.Fprintf(out, ", and %d relationship(s) an organization cannot have are kept to restore with it",
			len(rec.Dropped))
	}
	if err == nil {
		_, err = fmt.Fprintf(out, ". Undo with `amass review retract -proposal %s -reviewer %s`.\n", id, reviewer)
	}
	return err
}

// rejectOrgNamed records that a pending proposal's person is a person.
func rejectOrgNamed(j *review.Journal, id, reviewer string, out io.Writer) error {
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}
	if err := review.RejectOrgNamed(j, id, reviewer); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; the person was kept.\n", id)
	return err
}

// retractOrgNamed undoes an applied conversion.
func retractOrgNamed(ctx context.Context, w review.PersonConverter, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	restored, err := review.RetractOrgNamed(ctx, w, j, id, reviewer)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(out, "Retracted %s; the person is restored [%s] with its relationships.\n", id, restored)
	return err
}
