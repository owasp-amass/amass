// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"math"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// The infrastructure signal catalog defines the evidence that ties a netblock or
// an autonomous system to a target organization. The related-infrastructure
// lens, the runtime scope-expansion decision and the classifier read it, so all
// three share one source of truth (ai-design-principles.md, principle 8).
var infrastructureSignalsJSON = semantics.File("infrastructure_signals.json")

// Infrastructure signal IDs, as used in code and in infrastructure_signals.json.
const (
	SigIPNetRegistrantOrg   = "ipnet-registrant-org"
	SigASNRegistrantOrg     = "asn-registrant-org"
	SigASNAnnouncedNetblock = "asn-announced-netblock"
)

// Infrastructure signal matchers: how each signal is found in the graph.
const (
	matchInfraIPNetReg    = "ipnet_registrant_org"
	matchInfraASNReg      = "asn_registrant_org"
	matchInfraASNAnnounce = "asn_announced_netblock"
)

var infrastructureMatchers = map[string]bool{matchInfraIPNetReg: true, matchInfraASNReg: true,
	matchInfraASNAnnounce: true}

var loadInfrastructureCatalog = sync.OnceValues(func() (signalCatalog, error) {
	var c signalCatalog
	if err := graph.DecodeStrict(infrastructureSignalsJSON, &c); err != nil {
		return c, fmt.Errorf("infrastructure_signals.json: %w", err)
	}

	return c, validateInfrastructureSignals(c.Signals)
})

func validateInfrastructureSignals(signals []OwnershipSignal) error {
	seen := map[string]bool{}
	for _, s := range signals {
		switch {
		case s.ID == "" || seen[s.ID]:
			return fmt.Errorf("signal %q: missing or repeated id", s.ID)
		case s.Title == "" || s.Kind == "" || s.Finds == "" || s.Rationale == "":
			return fmt.Errorf("signal %s: title, kind, finds and rationale are required", s.ID)
		case s.Strength != StrengthStrong && s.Strength != StrengthSupporting:
			return fmt.Errorf("signal %s: strength must be strong or supporting", s.ID)
		case s.Weight <= 0 || s.Weight > signalCatalogMaxWeight:
			return fmt.Errorf("signal %s: weight must be in (0, 1]", s.ID)
		case !infrastructureMatchers[s.Matcher]:
			return fmt.Errorf("signal %s: unknown matcher %q", s.ID, s.Matcher)
		case len(s.Guards) == 0 || len(s.CounterIndications) == 0:
			return fmt.Errorf("signal %s: guards and counter_indications are required", s.ID)
		}

		seen[s.ID] = true
	}

	return nil
}

// InfrastructureSignals returns the infrastructure correlation signal catalog.
func InfrastructureSignals() []OwnershipSignal {
	c, err := loadInfrastructureCatalog()
	if err != nil {
		panic(err)
	}

	return c.Signals
}

// LookupInfrastructureSignal returns the catalog entry for id.
func LookupInfrastructureSignal(id string) (OwnershipSignal, bool) {
	for _, s := range InfrastructureSignals() {
		if s.ID == id {
			return s, true
		}
	}

	return OwnershipSignal{}, false
}

// InfrastructureScore combines the catalog weights of a candidate's signal ids
// with the shared noisy-OR scorer and reports whether the set includes a strong
// signal. A set with no strong signal (announcement alone) is corroboration
// only: the scope-expansion decision treats it as needing review.
func InfrastructureScore(ids []string) (confidence int, strong bool) {
	return signalScore(ids, LookupInfrastructureSignal)
}

// InfrastructureConfidence is the 0-100 confidence for a single signal id (its
// catalog weight times 100). An unknown id yields 0.
func InfrastructureConfidence(id string) int {
	s, ok := LookupInfrastructureSignal(id)
	if !ok {
		return 0
	}

	return int(math.Round(s.Weight * 100))
}

// InfrastructureSignalsMarkdown renders the infrastructure catalog as the user
// documentation in docs/ai/INFRASTRUCTURE.md.
func InfrastructureSignalsMarkdown() string {
	c, err := loadInfrastructureCatalog()
	if err != nil {
		panic(err)
	}

	var b strings.Builder
	b.WriteString("# Infrastructure correlation\n\n")
	b.WriteString("<!-- Generated from internal/semantics/infrastructure_signals.json by `amass review " +
		"infrastructure-signals -format markdown`. Edit that file, not this one. -->\n\n")
	b.WriteString("Infrastructure correlation associates more netblocks and autonomous systems with a target " +
		"organization, so an enumeration's scope can be made more complete. Each kind of evidence is a signal, listed " +
		"here with why it counts, what stops it from misfiring, and when it can still mislead. The same text is shown " +
		"by `amass review infrastructure-signals`.\n\n")
	b.WriteString("## How signals decide\n\n")
	b.WriteString("- The scope-expansion decision scores a candidate over these signals, with privacy-proxy registrant " +
		"organizations excluded and a name match never sufficient on its own; a strong signal (an RIR registration " +
		"naming the organization) may widen scope, while a supporting signal alone (a prefix merely announced by the " +
		"organization's AS) needs review.\n\n")
	b.WriteString("| Signal | Strength | Kind | Weight |\n| --- | --- | --- | --- |\n")
	for _, s := range c.Signals {
		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %.2f |\n", s.Title, s.ID, s.Strength, s.Kind, s.Weight)
	}
	for _, s := range c.Signals {
		fmt.Fprintf(&b, "\n<a id=\"%s\"></a>\n## %s\n\n", s.ID, s.Title)
		fmt.Fprintf(&b, "`%s`: %s %s signal, weight %.2f (confidence %d).\n\n", s.ID, s.Strength, s.Kind, s.Weight,
			InfrastructureConfidence(s.ID))
		fmt.Fprintf(&b, "**Finds:** %s\n\n**Why it counts:** %s\n", s.Finds, s.Rationale)
		writeList(&b, "Guards", s.Guards)
		writeList(&b, "Can still mislead when", s.CounterIndications)
	}

	return b.String()
}

// InfrastructureSignalsText renders the infrastructure catalog for a terminal.
func InfrastructureSignalsText() string {
	var b strings.Builder
	for i, s := range InfrastructureSignals() {
		if i > 0 {
			b.WriteString("\n")
		}

		fmt.Fprintf(&b, "%s (%s): %s %s signal, weight %.2f (confidence %d)\n", s.Title, s.ID, s.Strength, s.Kind,
			s.Weight, InfrastructureConfidence(s.ID))
		fmt.Fprintf(&b, "  Finds: %s\n  Why it counts: %s\n", s.Finds, s.Rationale)
		for _, g := range s.Guards {
			fmt.Fprintf(&b, "  Guard: %s\n", g)
		}
		for _, c := range s.CounterIndications {
			fmt.Fprintf(&b, "  Can mislead: %s\n", c)
		}
	}

	return b.String()
}
