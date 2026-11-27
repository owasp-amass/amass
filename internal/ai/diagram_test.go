// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

func TestGapDiagram(t *testing.T) {
	if GapDiagram(lens.OwnershipGapReport{}) != "" {
		t.Fatal("a report with no candidates should produce no diagram")
	}

	r := lens.OwnershipGapReport{
		Owner: graph.Asset{ID: "o", Type: "Organization", Key: "OWASP Foundation",
			Content: map[string]any{"name": "OWASP Foundation"}},
		Candidates: []lens.GapCandidate{
			{AssetID: "c-cr", Type: "ContactRecord", Asset: "https://rdap.example/labs", Decision: lens.GapReview,
				Attachment: &lens.ProposedEdge{FromID: "c-cr", ToID: "o", Label: "organization"}},
			{AssetID: "c-url", Type: "URL", Asset: "https://typo.example", Decision: lens.GapPropose,
				Attachment: &lens.ProposedEdge{FromID: "o", ToID: "c-url", Label: "website"}},
		},
		Truncated: true,
	}

	d := GapDiagram(r)
	for _, want := range []string{
		"flowchart LR",
		`owner["Organization: OWASP Foundation"]`,
		`c0["ContactRecord: https://rdap.example/labs"]`,
		"c0 -.->|review: organization| owner", // a candidate attributed to the subject
		"class c0 review",
		"owner ==>|propose: website| c1", // a subject-owned asset (Organization --website--> URL)
		"class c1 propose",
		"class owner subject",
		"classDef propose",
		"Partial: the gap search was truncated",
	} {
		if !strings.Contains(d, want) {
			t.Errorf("diagram missing %q:\n%s", want, d)
		}
	}
}
