// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/ai"
)

// listDuplicates compares the stored organizations and prints the pairs
// the duplicate signals link. Proposed and review pairs are recorded in the
// journal as merge proposals; nothing in the Asset Database changes.
func listDuplicates(ctx context.Context, graph ai.Graph, journalPath, format string, explicit bool,
	out, errout io.Writer) error {
	r, err := ai.FindDuplicateOrganizations(ctx, graph)
	if err != nil {
		return err
	}
	if journalPath != "" {
		added, err := (&ai.Journal{Path: journalPath}).SubmitDuplicates(ai.DuplicateProposals(r))
		if err != nil {
			return fmt.Errorf("record merge proposals: %w", err)
		}

		_, _ = fmt.Fprintf(errout, "%d new merge proposal(s) recorded in %s; review with `amass review proposals`\n",
			len(added), journalPath)
	}

	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, ai.FormatDuplicateReport(r))
		return err
	case format == "json":
		return writeJSON(out, r)
	}

	return fmt.Errorf("duplicates format %q: use text or json", format)
}
