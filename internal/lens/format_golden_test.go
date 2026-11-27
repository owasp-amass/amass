// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"flag"
	"os"
	"path/filepath"
	"testing"
)

// updateGolden rewrites the golden files from the current formatters:
//
//	go test ./internal/lens -run TestFormatGolden -update
//
// Review the diff before committing it.
var updateGolden = flag.Bool("update", false, "rewrite the lens formatter golden files")

// TestFormatGolden locks the terminal rendering of the review and correlation
// formatters, which had no test: a change to their wording or layout shows up
// as a golden-file diff. Each case renders a populated report and, where the
// formatter has one, its empty or partial form.
func TestFormatGolden(t *testing.T) {
	cases := map[string]string{
		"identity": FormatIdentityReport(IdentityReport{
			Organizations: 12,
			Reads:         340,
			Conflicts: []IdentityConflict{{
				ID:           "idc-1",
				Organization: "utica university",
				OrgID:        "6295",
				LegalName:    "the trustees of utica university",
				Jurisdiction: "US-NY",
				Reasons: []string{
					"the legal name matches none of the names other sources gave it (Utica University)",
					"the registration was attached by a name search (GLEIF)",
				},
			}},
		}),
		"identity_empty_partial": FormatIdentityReport(IdentityReport{
			Organizations: 3, Reads: 20000, Truncated: true, Reason: "database read limit",
		}),
		"related_domains": FormatRelatedDomainsReport(RelatedDomainsReport{
			OrgID: "108",
			Org:   "SUNY Polytechnic Institute",
			Domains: []HorizontalDomain{
				{Domain: "sunypoly.edu", Confidence: 90,
					Signals: []string{"shared analytics ID", "DMARC reports to an owned domain"}},
				{Domain: "sunyit.edu", Confidence: 60, Signals: []string{"shared favicon"}},
			},
		}),
		"related_domains_empty_partial": FormatRelatedDomainsReport(RelatedDomainsReport{
			OrgID: "108", Org: "SUNY Polytechnic Institute", Truncated: "database read limit",
		}),
		"related_infrastructure": FormatRelatedInfrastructureReport(RelatedInfrastructureReport{
			OrgID: "42",
			Org:   "OWASP Foundation",
			Assets: []InfrastructureAsset{
				{AssetType: "Netblock", Asset: "203.0.113.0/24", Confidence: 85,
					Signals: []string{"registered to the organization", "announced by its AS"}},
				{AssetType: "AutonomousSystem", Asset: "64500", Confidence: 80,
					Signals: []string{"registered to the organization"}},
			},
		}),
		"related_infrastructure_empty": FormatRelatedInfrastructureReport(RelatedInfrastructureReport{
			OrgID: "42", Org: "OWASP Foundation",
		}),
		"person_named": FormatPersonNamedReport(PersonNamedReport{
			Organizations: 40,
			Reads:         512,
			Candidates: []PersonNamedOrg{{
				ID: "pno-1", OrgID: "77", Organization: "jane doe", PersonID: "78", Person: "Jane Doe",
				ContactIDs: []string{"cr-1", "cr-2"}, Domains: []string{"janedoe.example"},
			}},
		}),
		"person_named_empty": FormatPersonNamedReport(PersonNamedReport{Organizations: 40, Reads: 512}),
		"person_duplicates": FormatPersonDuplicateReport(PersonDuplicateReport{
			Persons: 25,
			Candidates: []PersonDuplicate{{
				SurvivorID: "301", Survivor_: "Jane Q. Doe", DuplicateID: "302", Duplicate_: "Jane Doe",
				Signals: []string{"same email address", "same organization"},
			}},
		}),
		"relation": FormatRelationReport(RelationReport{
			Kind: "org_unit",
			Candidates: []RelationCandidate{{
				FromID: "10", From: "State University of New York", Label: "org_unit",
				ToID: "11", To: "SUNY Polytechnic Institute", Confidence: 75,
				Signals:     []string{"acronym of the parent's name", "shared street address"},
				EvidenceIDs: []string{"loc-5"},
			}},
		}),
		"relation_empty": FormatRelationReport(RelationReport{Kind: "org_unit"}),
	}

	for name, got := range cases {
		path := filepath.Join("testdata", "format", name+".golden")
		if *updateGolden {
			if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(got), 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}

		want, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("%s: no golden file (run go test ./internal/lens -run TestFormatGolden -update): %v", name, err)
			continue
		}
		if got != string(want) {
			t.Errorf("%s: output differs from %s\n--- got ---\n%s\n--- want ---\n%s", name, path, got, want)
		}
	}
}
