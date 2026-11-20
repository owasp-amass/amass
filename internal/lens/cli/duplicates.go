// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// brandKeyEnsurer materializes organization brand_key tags so a shared brand
// can be grouped in the database before the sweep runs. The OAM adapter
// implements it; fakes and stores without the capability do not, and the sweep
// still works from whatever brand keys are already stored.
type brandKeyEnsurer interface {
	EnsureBrandKeys(ctx context.Context, limit int) (int, error)
}

// listDuplicates compares the stored organizations and prints the pairs
// the duplicate signals link. Proposed and review pairs are recorded in the
// journal as merge proposals; nothing in the Asset Database changes.
func listDuplicates(ctx context.Context, graph graph.Graph, journalPath, format string, explicit bool,
	out, errout io.Writer) error {
	// Bring brand keys current so brand-based grouping is complete; a failure
	// here only means brand grouping sees fewer organizations, so it is noted
	// and the sweep proceeds.
	if e, ok := graph.(brandKeyEnsurer); ok {
		if n, err := e.EnsureBrandKeys(ctx, 0); err != nil {
			_, _ = fmt.Fprintf(errout, "brand-key backfill: %v\n", err)
		} else if n > 0 {
			_, _ = fmt.Fprintf(errout, "materialized %d organization brand key(s)\n", n)
		}
	}

	r, err := lens.FindDuplicateOrganizations(ctx, graph)
	if err != nil {
		return err
	}
	if journalPath != "" {
		added, err := (&review.Journal{Path: journalPath}).SubmitDuplicates(review.DuplicateProposals(r))
		if err != nil {
			return fmt.Errorf("record merge proposals: %w", err)
		}

		_, _ = fmt.Fprintf(errout, "%d new merge proposal(s) recorded in %s; review with `amass review proposals`\n",
			len(added), journalPath)
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatDuplicateReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("duplicates format %q: use text or json", format)
}
