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

func TestDelegatesTo(t *testing.T) {
	cases := map[string]string{
		"v=spf1 include:_spf.example.com ~all":                        "include:_spf.example.com",
		"v=spf1 ip4:192.0.2.0/24 redirect=example.com":                "redirect:example.com",
		"v=spf1 +include:example.com -all":                            "include:example.com",
		"v=spf1 include:notexample.com ~all":                          "",
		"v=DMARC1; p=reject; rua=mailto:d@example.com,mailto:x@y.org": "rua:example.com",
		"v=DMARC1; p=none; ruf=mailto:f@reports.example.com!10m":      "ruf:reports.example.com",
		"v=DMARC1; p=none; rua=mailto:d@vendor.example":               "",
		"google-site-verification=example.com":                        "",
	}
	for txt, want := range cases {
		if got := delegatesTo(txt, "example.com"); got != want {
			t.Errorf("delegatesTo(%q) = %q, want %q", txt, got, want)
		}
	}
}

func TestSignalCatalogIsValid(t *testing.T) {
	signals := OwnershipSignals()
	if len(signals) < 8 {
		t.Fatalf("catalog has %d signals", len(signals))
	}
	for _, s := range signals {
		if len(s.Guards) == 0 || len(s.CounterIndications) == 0 {
			t.Errorf("signal %s documents no guards or counter-indications", s.ID)
		}
	}
	for _, id := range []string{sigSharedRegistrant, sigHosting, sigColisting, sigSelfHostedDNS} {
		if _, ok := LookupOwnershipSignal(id); !ok {
			t.Errorf("signal %s used in code is missing from the catalog", id)
		}
	}
	if err := validateSignals(append(slices.Clone(signals), signals[0])); err == nil {
		t.Error("a repeated signal id was accepted")
	}
}

// TestSignalsDocIsCurrent keeps docs/ai/SIGNALS.md generated from the
// catalog. Regenerate it with AMASS_UPDATE_SIGNALS_DOC=1 go test -run
// TestSignalsDocIsCurrent ./internal/lens/.
func TestSignalsDocIsCurrent(t *testing.T) {
	path := filepath.Join("..", "..", "docs", "ai", "SIGNALS.md")
	want := SignalsMarkdown()
	if os.Getenv("AMASS_UPDATE_SIGNALS_DOC") != "" {
		if err := os.WriteFile(path, []byte(want), 0644); err != nil {
			t.Fatal(err)
		}
	}

	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Error("docs/ai/SIGNALS.md is out of date; regenerate it with AMASS_UPDATE_SIGNALS_DOC=1 go test -run " +
			"TestSignalsDocIsCurrent ./internal/lens/")
	}
}
