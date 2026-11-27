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

// personNameKeyEnsurer materializes person_name_key tags before the sweep so a
// shared family name can be grouped in the database. The OAM adapter implements
// it; fakes and stores without the capability do not.
type personNameKeyEnsurer interface {
	EnsurePersonNameKeys(ctx context.Context, limit int) (int, error)
}

// listPersonDuplicates compares the stored persons and prints the pairs that
// look like the same person — a variant of the same name plus a shared
// organization or identifier. Each pair is recorded in the journal as a
// review-gated merge proposal; nothing in the Asset Database changes until a
// reviewer approves it.
func listPersonDuplicates(ctx context.Context, graph graph.Graph, j *review.Journal, format string, explicit bool,
	out, errout io.Writer) error {
	// Bring person-name keys current so family-name grouping is complete; a
	// failure here only narrows grouping, so it is noted and the sweep proceeds.
	if e, ok := graph.(personNameKeyEnsurer); ok {
		if n, err := e.EnsurePersonNameKeys(ctx, 0); err != nil {
			_, _ = fmt.Fprintf(errout, "person-name-key backfill: %v\n", err)
		} else if n > 0 {
			_, _ = fmt.Fprintf(errout, "materialized %d person name key(s)\n", n)
		}
	}

	r, err := lens.FindPersonDuplicates(ctx, graph)
	if err != nil {
		return err
	}
	if j != nil {
		added, err := j.SubmitDuplicates(review.PersonDuplicateProposals(r))
		if err != nil {
			return fmt.Errorf("record person-merge proposals: %w", err)
		}

		_, _ = fmt.Fprintf(errout, "%d new person-merge proposal(s) recorded in %s; review with "+
			"`amass review proposals`\n", len(added), j.Name())
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.FormatPersonDuplicateReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("person-duplicates format %q: use text or json", format)
}
