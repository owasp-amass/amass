// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	_ "embed"
	"fmt"
	"strings"
	"sync"
)

// The duplicate signal catalog defines the evidence used to propose that
// two organizations are one company, with the rationale shown to users.
//
//go:embed semantics/duplicate_signals.json
var duplicateSignalsJSON []byte

// Duplicate signal matchers.
const (
	matchSharedIdentifier     = "shared_identifier"
	matchSharedRegistration   = "shared_registration"
	matchSharedContactRecord  = "shared_contact_record"
	matchSameBrand            = "same_brand"
	matchSharedLocation       = "shared_location"
	matchAbbreviation         = "abbreviation"
	matchJurisdictionConflict = "jurisdiction_conflict"
	matchConflictingID        = "conflicting_identifier"
	matchParentChild          = "parent_child"
)

var duplicateMatchers = map[string]bool{matchSharedIdentifier: true, matchSharedRegistration: true,
	matchSharedContactRecord: true, matchSameBrand: true, matchSharedLocation: true, matchAbbreviation: true,
	matchJurisdictionConflict: true, matchConflictingID: true, matchParentChild: true}

// duplicateNegative are the matchers that count against a merge.
var duplicateNegative = map[string]bool{matchJurisdictionConflict: true, matchConflictingID: true,
	matchParentChild: true}

var loadDuplicateCatalog = sync.OnceValues(func() (signalCatalog, error) {
	var c signalCatalog
	if err := decodeStrict(duplicateSignalsJSON, &c); err != nil {
		return c, fmt.Errorf("duplicate_signals.json: %w", err)
	}

	return c, validateDuplicateSignals(c.Signals)
})

func validateDuplicateSignals(signals []OwnershipSignal) error {
	seen := map[string]bool{}
	for _, s := range signals {
		switch {
		case s.ID == "" || seen[s.ID]:
			return fmt.Errorf("signal %q: missing or repeated id", s.ID)
		case s.Title == "" || s.Kind == "" || s.Finds == "" || s.Rationale == "":
			return fmt.Errorf("signal %s: title, kind, finds and rationale are required", s.ID)
		case s.Strength != StrengthStrong && s.Strength != StrengthSupporting && s.Strength != StrengthNegative:
			return fmt.Errorf("signal %s: strength must be strong, supporting or negative", s.ID)
		case s.Weight <= 0 || s.Weight > signalCatalogMaxWeight:
			return fmt.Errorf("signal %s: weight must be in (0, 1]", s.ID)
		case !duplicateMatchers[s.Matcher]:
			return fmt.Errorf("signal %s: unknown matcher %q", s.ID, s.Matcher)
		case (s.Matcher == matchSharedIdentifier || s.Matcher == matchConflictingID) && len(s.Params.IDTypes) == 0:
			return fmt.Errorf("signal %s: id_types required", s.ID)
		case s.Matcher == matchSameBrand && len(s.Params.LegalForms) == 0:
			return fmt.Errorf("signal %s: legal_forms required", s.ID)
		case s.Matcher == matchAbbreviation && s.Params.MinLength < 3:
			return fmt.Errorf("signal %s: min_length must be at least 3", s.ID)
		case s.Matcher == matchParentChild && len(s.Params.Labels) == 0:
			return fmt.Errorf("signal %s: labels required", s.ID)
		case (s.Strength == StrengthNegative) != duplicateNegative[s.Matcher]:
			return fmt.Errorf("signal %s: only conflict matchers are negative", s.ID)
		case s.Matcher == matchSameBrand && s.Strength == StrengthStrong:
			// A name is shared by unrelated companies in other jurisdictions.
			return fmt.Errorf("signal %s: a name signal cannot be strong", s.ID)
		}

		seen[s.ID] = true
	}

	return nil
}

// DuplicateSignals returns the duplicate-organization signal catalog.
func DuplicateSignals() []OwnershipSignal {
	c, err := loadDuplicateCatalog()
	if err != nil {
		panic(err)
	}

	return c.Signals
}

func duplicateSignal(id string) (OwnershipSignal, bool) {
	for _, s := range DuplicateSignals() {
		if s.ID == id {
			return s, true
		}
	}

	return OwnershipSignal{}, false
}

// legalForms returns the legal-form suffixes removed before names are
// compared, from the same_brand matcher's parameters.
var legalForms = sync.OnceValue(func() map[string]bool {
	out := map[string]bool{}
	for _, s := range DuplicateSignals() {
		if s.Matcher != matchSameBrand {
			continue
		}
		for _, f := range s.Params.LegalForms {
			if f = normLegalForm(f); f != "" {
				out[f] = true
			}
		}
	}

	return out
})

func normLegalForm(s string) string {
	return strings.Trim(strings.ToLower(strings.TrimSpace(s)), ".,")
}

// DuplicateSignalsMarkdown renders the duplicate catalog as the user
// documentation in docs/ai/DUPLICATES.md.
func DuplicateSignalsMarkdown() string {
	var b strings.Builder
	b.WriteString("# Duplicate organizations\n\n")
	b.WriteString("<!-- Generated from internal/ai/semantics/duplicate_signals.json by `amass ai duplicate-signals " +
		"-format markdown`. Edit that file, not this one. -->\n\n")
	b.WriteString("Sources record one company several times: a certificate, an RDAP lookup and GLEIF can each create " +
		"an organization under a different spelling. Amass proposes merging two stored organizations only from " +
		"stored evidence. Each kind of evidence is a signal, listed here with why it counts, what stops it from " +
		"misfiring, and when it can still mislead. The same text is shown by `amass ai duplicate-signals`.\n\n")
	b.WriteString("## How signals decide\n\n")
	b.WriteString("- Two strong signals, or one strong signal and a different signal that is not a tiebreaker, " +
		"**propose** a merge. During enumeration a proposed merge is applied automatically when the session ends " +
		"(with the `amass-ai` source on every moved relationship) unless attribution is set to `journal` or `off`.\n")
	b.WriteString("- One strong signal, or two signals of any strength, **needs review**: it waits in the review " +
		"journal for a person. A pair linked only by its name, with nothing against it, also needs review.\n")
	b.WriteString("- A **negative** signal lowers the score and keeps a pair from being merged automatically; without " +
		"a strong signal it also keeps the pair out of review.\n")
	b.WriteString("- A matching name is never strong: organizations in different jurisdictions often share a name and " +
		"are different companies.\n")
	b.WriteString("- A merge moves the duplicate's properties and relationships onto the organization that has more " +
		"recorded evidence, then deletes the duplicate. The journal records everything the merge changed, so " +
		"`amass ai -proposal <id> -reviewer <name> retract` restores the duplicate and removes only what the merge " +
		"added.\n\n")
	b.WriteString("| Signal | Strength | Kind | Weight |\n| --- | --- | --- | --- |\n")
	for _, s := range DuplicateSignals() {
		strength := s.Strength
		if s.Tiebreaker {
			strength += " (tiebreaker)"
		}

		fmt.Fprintf(&b, "| [%s](#%s) | %s | %s | %.2f |\n", s.Title, s.ID, strength, s.Kind, s.Weight)
	}
	for _, s := range DuplicateSignals() {
		fmt.Fprintf(&b, "\n<a id=\"%s\"></a>\n## %s\n\n", s.ID, s.Title)
		tie := ""
		if s.Tiebreaker {
			tie = " Tiebreaker."
		}

		fmt.Fprintf(&b, "`%s`: %s %s signal, weight %.2f.%s\n\n", s.ID, s.Strength, s.Kind, s.Weight, tie)
		fmt.Fprintf(&b, "**Finds:** %s\n\n**Why it counts:** %s\n", s.Finds, s.Rationale)
		writeList(&b, "Guards", s.Guards)
		writeList(&b, "Can still mislead when", s.CounterIndications)
		if len(s.Params.IDTypes) > 0 {
			fmt.Fprintf(&b, "\n**Identifier types:** `%s`\n", strings.Join(s.Params.IDTypes, "`, `"))
		}
	}

	return b.String()
}

// DuplicateSignalsText renders the duplicate catalog for a terminal.
func DuplicateSignalsText() string {
	var b strings.Builder
	for i, s := range DuplicateSignals() {
		if i > 0 {
			b.WriteString("\n")
		}

		tie := ""
		if s.Tiebreaker {
			tie = ", tiebreaker"
		}

		fmt.Fprintf(&b, "%s (%s): %s %s signal, weight %.2f%s\n", s.Title, s.ID, s.Strength, s.Kind, s.Weight, tie)
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
