// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// A run prints one line per document; a dry run also shows what it would
// store, quotes included.
func TestWriteDocumentRun(t *testing.T) {
	run := ai.DocumentRun{Read: 1, Skipped: 2, Remaining: 3, Failed: 1, Statements: 3, Rejected: 1, DryRun: true,
		Documents: []ai.DocumentResult{
			{URL: "https://a.example/plan.pdf", Category: "annual_report", Chunks: 2, Statements: 3, Rejected: 1,
				Stored: []review.StoredStatement{
					{Kind: ai.FindingRelation, Subject: "Foundation", SubjectType: "Organization", Predicate: "unit_of",
						Object: "College", ObjectType: "Organization", Quote: "The Foundation is a division of the College."},
					{Kind: ai.FindingAsset, Subject: "vpn.a.example", SubjectType: "FQDN", Quote: "through vpn.a.example"},
					{Kind: ai.FindingAttribute, Subject: "College", SubjectType: "Organization", Field: "founding_date",
						Object: "1966", Quote: "founded in 1966"},
				}},
			{URL: "https://a.example/b.pdf", Error: "fetch: status 404 Not Found", Failure: ai.FailureFetch},
		}, Failures: map[string]int{ai.FailureFetch: 1}}
	var out bytes.Buffer
	if err := writeDocumentRun(&out, "a.example", run); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"https://a.example/plan.pdf: read 2 part(s), would store 3 findings (category annual_report), rejected 1",
		`Organization Foundation -[unit_of]-> Organization College: "The Foundation is a division of the College."`,
		`FQDN vpn.a.example: "through vpn.a.example"`,
		`Organization College founding_date = 1966`,
		"https://a.example/b.pdf: failed (fetch): fetch: status 404 Not Found",
		"failed by why: fetch 1",
		"read 1 documents, skipped 2 already read, 3 remaining, failed 1",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in:\n%s", want, out.String())
		}
	}

	out.Reset()
	_ = writeDocumentRun(&out, "b.example", ai.DocumentRun{})
	if !strings.Contains(out.String(), "no stored documents for b.example") {
		t.Errorf("empty run: %q", out.String())
	}
}
