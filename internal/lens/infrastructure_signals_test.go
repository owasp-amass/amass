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

func TestInfrastructureSignalCatalogIsValid(t *testing.T) {
	signals := InfrastructureSignals()
	if len(signals) < 2 {
		t.Fatalf("catalog has %d signals", len(signals))
	}
	for _, s := range signals {
		if len(s.Guards) == 0 || len(s.CounterIndications) == 0 {
			t.Errorf("signal %s documents no guards or counter-indications", s.ID)
		}
	}
	for _, id := range []string{SigIPNetRegistrantOrg, SigASNRegistrantOrg} {
		if _, ok := LookupInfrastructureSignal(id); !ok {
			t.Errorf("signal %s used in code is missing from the catalog", id)
		}
	}
	if err := validateInfrastructureSignals(append(slices.Clone(signals), signals[0])); err == nil {
		t.Error("a repeated signal id was accepted")
	}
}

func TestInfrastructureScore(t *testing.T) {
	cases := map[string]int{SigIPNetRegistrantOrg: 75, SigASNRegistrantOrg: 75}
	for id, want := range cases {
		if got := InfrastructureConfidence(id); got != want {
			t.Errorf("InfrastructureConfidence(%q) = %d, want %d", id, got, want)
		}
		if c, strong := InfrastructureScore([]string{id}); c != want || !strong {
			t.Errorf("InfrastructureScore(%q) = (%d, %v), want (%d, true)", id, c, strong, want)
		}
	}
	if InfrastructureConfidence("nope") != 0 {
		t.Error("an unknown signal id should yield confidence 0")
	}
	if c, _ := InfrastructureScore(nil); c != 0 {
		t.Errorf("empty score = %d, want 0", c)
	}
}

func TestInfrastructureSignalsDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "ai", "INFRASTRUCTURE.md")
	want := InfrastructureSignalsMarkdown()
	if os.Getenv("AMASS_UPDATE_INFRASTRUCTURE_DOC") != "" {
		if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Error("docs/ai/INFRASTRUCTURE.md is out of date; regenerate it with AMASS_UPDATE_INFRASTRUCTURE_DOC=1 " +
			"go test -run TestInfrastructureSignalsDocIsCurrent ./internal/lens/")
	}
}
