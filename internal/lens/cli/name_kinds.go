// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// approveNameKind decides a pending name proposal as a person or an
// organization and writes the record for it; with it, every pending proposal
// of the same name in the same field, unless only is set.
func approveNameKind(ctx context.Context, w review.NameKindApplier, j *review.Journal, id, as, reviewer string,
	only bool, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if as == "" {
		return fmt.Errorf("say what %s names with -as %s or -as %s", id, review.NameKindPerson,
			review.NameKindOrganization)
	}

	outcomes, err := review.ApplyNameKindGroup(ctx, w, j, id, as, reviewer, 100, "", only)
	for _, o := range outcomes {
		verb := "Linked the existing"
		if o.Created {
			verb = "Created the"
		}
		if _, werr := fmt.Fprintf(out, "%s %s [%s] for %s. Undo with `amass review retract -proposal %s`.\n",
			verb, as, o.EntityID, o.ProposalID, o.ProposalID); werr != nil && err == nil {
			err = werr
		}
	}
	return err
}

// rejectNameKind records that a pending name stays a name on its record;
// with it, every pending proposal of the same name in the same field, unless
// only is set.
func rejectNameKind(j *review.Journal, id, reviewer string, only bool, out io.Writer) error {
	ids, err := review.RejectNameKindGroup(j, id, reviewer, only)
	for _, rid := range ids {
		if _, werr := fmt.Fprintf(out, "Rejected %s; the name stays on its record and nothing was written.\n",
			rid); werr != nil && err == nil {
			err = werr
		}
	}
	return err
}

// retractNameKind undoes an applied name proposal.
func retractNameKind(ctx context.Context, w review.NameKindApplier, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	if err := review.RetractNameKind(ctx, w, j, id, reviewer); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Retracted %s; the name is kept on its record again.\n", id)
	return err
}
