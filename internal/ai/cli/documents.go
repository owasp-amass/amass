// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// writeDocumentRun prints a documents run, one line per document read.
func writeDocumentRun(out io.Writer, root string, run ai.DocumentRun) error {
	if len(run.Documents) == 0 && run.Skipped == 0 && run.Remaining == 0 {
		_, err := fmt.Fprintf(out, "no stored documents for %s\n", root)
		return err
	}

	verb := "stored"
	if run.DryRun {
		verb = "would store"
	}
	for _, d := range run.Documents {
		if d.Error != "" {
			_, _ = fmt.Fprintf(out, "%s: failed (%s): %s\n", d.URL, d.Failure, d.Error)
			continue
		}
		category := d.Category
		if category == "" {
			category = "none"
		}
		_, _ = fmt.Fprintf(out, "%s: read %d part(s), %s %d findings (category %s), rejected %d", d.URL, d.Chunks,
			verb, d.Statements, category, d.Rejected)
		if d.ReadingID != "" {
			_, _ = fmt.Fprintf(out, " [%s]", d.ReadingID)
		}
		if d.Through > 0 {
			_, _ = fmt.Fprint(out, "; stopped at its part or time limit, the next reading continues")
		}
		_, _ = fmt.Fprintln(out)
		// a dry run shows what would be stored, quotes included
		if run.DryRun {
			for _, s := range d.Stored {
				_, _ = fmt.Fprintf(out, "    %s\n", findingLine(s))
			}
		}
	}

	_, err := fmt.Fprintf(out, "read %d documents, skipped %d already read, %d remaining, failed %d: "+
		"%d findings, %d rejected\n", run.Read, run.Skipped, run.Remaining, run.Failed, run.Statements, run.Rejected)
	// documents read only in part are among the remaining: the next reading
	// continues them
	if err == nil && run.Partial > 0 {
		_, err = fmt.Fprintf(out, "%d read in part, to be continued\n", run.Partial)
	}
	if err != nil || len(run.Failures) == 0 {
		return err
	}
	kinds := make([]string, 0, len(run.Failures))
	for k := range run.Failures {
		kinds = append(kinds, k)
	}
	sort.Strings(kinds)
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, fmt.Sprintf("%s %d", k, run.Failures[k]))
	}
	_, err = fmt.Fprintf(out, "failed by why: %s\n", strings.Join(parts, ", "))
	return err
}

// findingLine renders one stored finding.
func findingLine(s review.StoredStatement) string {
	var line string
	switch s.Kind {
	case ai.FindingAsset:
		line = fmt.Sprintf("%s %s", s.SubjectType, s.Subject)
	case ai.FindingAttribute:
		if s.Predicate != "" {
			line = fmt.Sprintf("%s %s %s", s.Subject, s.Predicate, s.Object)
		} else {
			line = fmt.Sprintf("%s %s %s = %s", s.SubjectType, s.Subject, s.Field, s.Object)
		}
	default:
		line = fmt.Sprintf("%s %s -[%s]-> %s %s", s.SubjectType, s.Subject, s.Predicate, s.ObjectType, s.Object)
		if s.Detail != "" {
			line += fmt.Sprintf(" (%s)", s.Detail)
		}
	}
	if s.Quote != "" {
		line += fmt.Sprintf(": %q", s.Quote)
	}
	return line
}
