// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// retractScopeExpansion records that a person retracted an applied scope
// expansion, so no later enumeration widens its scope to the asset again.
// What the run that admitted it collected stays in the database.
func retractScopeExpansion(j *review.Journal, id, reviewer string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	all, err := j.ScopeExpansions()
	if err != nil {
		return err
	}
	for _, e := range all {
		if e.ID != id {
			continue
		}
		if e.Status != review.ProposalApplied {
			return fmt.Errorf("scope expansion %s is %s, not applied", id, e.Status)
		}

		if err := j.RecordScopeExpansion(review.ScopeExpansion{ID: e.ID, OrgID: e.OrgID, Org: e.Org,
			AssetType: e.AssetType, Asset: e.Asset, Status: review.ProposalRetracted, Reviewer: reviewer}); err != nil {
			return err
		}
		_, err = fmt.Fprintf(out, "Retracted the scope expansion of %s %s for %s: later enumerations will not "+
			"widen their scope to it again. What earlier runs collected stays in the database.\n",
			e.Kind(), e.Asset, e.Org)
		return err
	}

	return fmt.Errorf("no scope expansion %s in the journal", id)
}

// decideScopeExpansion records a person's approval or rejection of a pending
// scope expansion.
func decideScopeExpansion(j *review.Journal, id, status, reviewer string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	e, err := review.DecideScopeExpansion(j, id, status, reviewer)
	if err != nil {
		return err
	}
	if status == review.ProposalRejected {
		_, err = fmt.Fprintf(out, "Rejected the scope expansion of %s %s for %s: no enumeration will widen its "+
			"scope to it.\n", e.Kind(), e.Asset, e.Org)
		return err
	}
	_, err = fmt.Fprintf(out, "Approved the scope expansion of %s %s for %s: the next enumeration that finds it "+
		"again admits it into scope. Undo with `amass review retract -proposal %s -reviewer %s`.\n",
		e.Kind(), e.Asset, e.Org, id, reviewer)
	return err
}
