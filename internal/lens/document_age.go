// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"slices"
	"time"

	"github.com/owasp-amass/amass/v5/internal/docmeta"
	"github.com/owasp-amass/amass/v5/internal/graph"
)

// DocumentStaleAge is how old a document's newest own date may be before its
// findings stop counting as current. A stale document's findings are still
// stored and shown, but they give no leads, no relation proposals and no
// classifier evidence, except what states history (a former name or a
// merger), which old documents record as well as new ones. Offices, staff,
// parents, operators and vendors change; a budget from fifteen years ago says
// little about who runs what today.
const DocumentStaleAge = 5 * 365 * 24 * time.Hour

// documentDateFormats are the forms a stored document date is read in.
var documentDateFormats = []string{time.RFC3339, "2006-01-02T15:04:05", "2006-01-02"}

// documentDated returns the newest date a File's metadata states
// (doc_modified or doc_created, RFC 3339 when the document's date parsed),
// or the zero time when it states none that
// parses. Dates before 1990 are tool defaults (1601, 1970), not real dates.
func documentDated(ev []graph.Evidence) time.Time {
	var newest time.Time
	for _, name := range []string{propDocModified, propDocCreated} {
		for _, v := range propertyValues(ev, name) {
			// a date stored before it could be parsed (such as a PDF date
			// written without its "D:" prefix) is read again here
			v = docmeta.NormalizeDate(v)
			for _, f := range documentDateFormats {
				t, err := time.Parse(f, v)
				if err != nil {
					continue
				}
				if t.Year() >= 1990 && t.After(newest) {
					newest = t
				}
				break
			}
		}
	}
	return newest
}

// StaleDocument reports whether a document dated dated is older than
// DocumentStaleAge at now. An undated document is not stale.
func StaleDocument(dated, now time.Time) bool {
	return !dated.IsZero() && now.Sub(dated) > DocumentStaleAge
}

// staleFinding reports whether a finding of a stale document is left out:
// every finding is, except one that states history (docFormerPredicates).
func staleFinding(stale bool, predicate string) bool {
	return stale && !slices.Contains(docFormerPredicates, predicate)
}
