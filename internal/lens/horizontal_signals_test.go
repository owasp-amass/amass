// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func TestHorizontalSignalCatalogIsValid(t *testing.T) {
	signals := HorizontalSignals()
	if len(signals) < 4 {
		t.Fatalf("catalog has %d signals", len(signals))
	}
	for _, s := range signals {
		if len(s.Guards) == 0 || len(s.CounterIndications) == 0 {
			t.Errorf("signal %s documents no guards or counter-indications", s.ID)
		}
	}
	// Every signal id used in code must be in the catalog.
	for _, id := range []string{SigRegistrantOrg, SigCertSubjectOrg, SigSharedNameServer, SigOfficialWebsite} {
		if _, ok := LookupHorizontalSignal(id); !ok {
			t.Errorf("signal %s used in code is missing from the catalog", id)
		}
	}
	if err := validateHorizontalSignals(append(slices.Clone(signals), signals[0])); err == nil {
		t.Error("a repeated signal id was accepted")
	}
}

// The related-domains lens derives its per-signal confidences from the catalog,
// so the catalog weights must map to the confidences the lens and its tests
// expect. This pins the single source of truth.
func TestHorizontalConfidencesFromCatalog(t *testing.T) {
	cases := map[string]int{
		SigRegistrantOrg:    70,
		SigCertSubjectOrg:   75,
		SigSharedNameServer: 65,
		SigOfficialWebsite:  80,
	}
	for id, want := range cases {
		if got := HorizontalConfidence(id); got != want {
			t.Errorf("HorizontalConfidence(%q) = %d, want %d", id, got, want)
		}
	}
	if HorizontalConfidence("no-such-signal") != 0 {
		t.Error("an unknown signal id should yield confidence 0")
	}
}

func TestHorizontalScore(t *testing.T) {
	// A single signal scores at its own confidence (weight x 100).
	if c, strong := HorizontalScore([]string{SigRegistrantOrg}); c != 70 || !strong {
		t.Errorf("single registrant = (%d, %v), want (70, true)", c, strong)
	}
	if c, strong := HorizontalScore([]string{SigOfficialWebsite}); c != 80 || !strong {
		t.Errorf("single website = (%d, %v), want (80, true)", c, strong)
	}
	// A lone supporting signal is not strong, so it must not auto-expand.
	if c, strong := HorizontalScore([]string{SigSharedNameServer}); c != 65 || strong {
		t.Errorf("single name server = (%d, %v), want (65, false)", c, strong)
	}
	// Independent signals corroborate: the pair scores higher than either alone,
	// and never exceeds 100.
	c, strong := HorizontalScore([]string{SigRegistrantOrg, SigCertSubjectOrg})
	if !strong || c <= 75 || c > 100 {
		t.Errorf("registrant+cert = (%d, %v), want strong and >75, <=100", c, strong)
	}
	// Repeated and unknown ids are ignored.
	if c, _ := HorizontalScore([]string{SigRegistrantOrg, SigRegistrantOrg, "nope"}); c != 70 {
		t.Errorf("deduped score = %d, want 70", c)
	}
	if c, strong := HorizontalScore(nil); c != 0 || strong {
		t.Errorf("empty = (%d, %v), want (0, false)", c, strong)
	}
}

// TestHorizontalSignalsDocIsCurrent keeps docs/ai/HORIZONTALS.md generated from
// the catalog. Regenerate it with AMASS_UPDATE_HORIZONTALS_DOC=1 go test -run
// TestHorizontalSignalsDocIsCurrent ./internal/lens/.
func TestHorizontalSignalsDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "ai", "HORIZONTALS.md")
	want := HorizontalSignalsMarkdown()
	if os.Getenv("AMASS_UPDATE_HORIZONTALS_DOC") != "" {
		if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Error("docs/ai/HORIZONTALS.md is out of date; regenerate it with AMASS_UPDATE_HORIZONTALS_DOC=1 go test " +
			"-run TestHorizontalSignalsDocIsCurrent ./internal/lens/")
	}
}
