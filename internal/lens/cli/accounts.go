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

	"github.com/owasp-amass/amass/v5/internal/graph/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// isAccountProposal reports whether an ID is an account proposal's.
func isAccountProposal(id string) bool { return strings.HasPrefix(id, "acct-") }

// listAccounts runs the accounts lens and, with a journal, records the
// accounts it computed as reviewed proposals, so an accepted one can be
// written as an Account asset.
func listAccounts(ctx context.Context, g oamrepo.Adapter, domain, org string, j *review.Journal, format string,
	out, errout io.Writer) error {
	root, err := groupRoot(ctx, g, domain, org)
	if err != nil {
		return err
	}

	r, err := lens.FindAccounts(ctx, g, oamrepo.Catalog{}, root, lens.LensLimits{})
	if err != nil {
		return err
	}

	if j != nil {
		added, err := j.SubmitAccounts(review.AccountProposals(r))
		if err != nil {
			return fmt.Errorf("record account proposals: %w", err)
		}
		if len(added) > 0 {
			_, _ = fmt.Fprintf(errout, "Recorded %d account proposal(s); review with `amass review proposals` "+
				"and accept with `amass review approve -proposal <id>`.\n", len(added))
		}
	}

	if format == "json" {
		return writeJSON(out, r)
	}
	_, err = fmt.Fprint(out, r.Text())
	return err
}

// approveAccount writes an accepted account proposal as an Account asset the
// owning organization controls.
func approveAccount(ctx context.Context, repo review.AccountApplier, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	p, err := j.PendingAccount(id)
	if err != nil {
		return err
	}

	edgeID, err := review.ApplyAccount(ctx, repo, p)
	if err != nil {
		return err
	}
	if err := j.RecordAccount(review.AccountOutcome{ProposalID: id, Status: review.ProposalApplied,
		Reviewer: reviewer, EdgeID: edgeID}); err != nil {
		return fmt.Errorf("account %s was written but the journal was not updated: %w", edgeID, err)
	}

	_, err = fmt.Fprintf(out, "Recorded %s account %q for %s as edge %s. Undo with "+
		"`amass review retract -proposal %s`.\n", p.Platform, p.Handle, p.Owner, edgeID, id)
	return err
}

// retractAccount removes the relationship an applied account proposal created
// and records the retraction.
func retractAccount(ctx context.Context, d review.AccountDeleter, j *review.Journal, id, reviewer string,
	out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	p, edgeID, err := j.AppliedAccount(id)
	if err != nil {
		return err
	}
	if edgeID != "" {
		if err := d.DeleteEdge(ctx, edgeID); err != nil {
			return fmt.Errorf("delete edge %s: %w", edgeID, err)
		}
	}
	if err := j.RecordAccount(review.AccountOutcome{ProposalID: id, Status: review.ProposalRetracted,
		Reviewer: reviewer, EdgeID: edgeID}); err != nil {
		return fmt.Errorf("edge %s was removed but the journal was not updated: %w", edgeID, err)
	}

	_, err = fmt.Fprintf(out, "Retracted the %s account %q for %s.\n", p.Platform, p.Handle, p.Owner)
	return err
}
