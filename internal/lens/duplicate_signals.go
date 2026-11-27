// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"strings"
	"sync"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// The duplicate signal catalog defines the evidence used to propose that
// two organizations are one company, with the rationale shown to users.
var duplicateSignalsJSON = semantics.File("duplicate_signals.json")

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
	matchJurisdictionConflict: true, matchConflictingID: true, matchParentChild: true,
	matchDocumentStatement: true}

// duplicateNegative are the matchers that count against a merge.
var duplicateNegative = map[string]bool{matchJurisdictionConflict: true, matchConflictingID: true,
	matchParentChild: true}

var loadDuplicateCatalog = sync.OnceValues(func() (signalCatalog, error) {
	var c signalCatalog
	if err := graph.DecodeStrict(duplicateSignalsJSON, &c); err != nil {
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

func DuplicateSignal(id string) (OwnershipSignal, bool) {
	for _, s := range DuplicateSignals() {
		if s.ID == id {
			return s, true
		}
	}

	return OwnershipSignal{}, false
}

// AutoMergeable reports whether a proposed merge's signals let it be applied
// without review: a registry identity signal (a shared registry identifier or
// network handle, or the same jurisdiction and registration number), or a
// shared contact record together with the same name. A registry identifier
// names one legal entity. A contact record is written by whoever registered
// the domain, and parents, subsidiaries and brand-protection firms reuse one
// for many entities, so on its own, or with only an address, it shows common
// control rather than one company: such a pair waits for review. A strong
// signal that rests on assistants' contributions (Contributed) counts for
// none of these.
func AutoMergeable(signals []GapSignal) bool {
	// document evidence never helps a merge be applied: the pair must be
	// proposed on its other evidence alone
	signals = WithoutDocumentSignals(signals)
	if _, decision := scoreSignals(signals, true, DuplicateSignal); decision != GapPropose {
		return false
	}

	contact, name := false, false
	for _, gs := range signals {
		s, ok := DuplicateSignal(gs.Signal)
		if !ok || gs.Contributed {
			continue
		}
		switch s.Matcher {
		case matchSharedIdentifier, matchSharedRegistration:
			return true
		case matchSharedContactRecord:
			contact = true
		case matchSameBrand:
			name = true
		}
	}
	return contact && name
}

// DuplicateSignalsMarkdown renders the duplicate catalog as the user
// documentation in docs/ai/DUPLICATES.md.
func DuplicateSignalsMarkdown() string {
	var b strings.Builder
	b.WriteString("# Duplicate organizations\n\n")
	b.WriteString("<!-- Generated from internal/semantics/duplicate_signals.json by `amass review duplicate-signals " +
		"-format markdown`. Edit that file, not this one. -->\n\n")
	b.WriteString("Sources record one company several times: a certificate, an RDAP lookup and GLEIF can each create " +
		"an organization under a different spelling. Amass proposes merging two stored organizations only from " +
		"stored evidence. Each kind of evidence is a signal, listed here with why it counts, what stops it from " +
		"misfiring, and when it can still mislead. The same text is shown by `amass review duplicate-signals`.\n\n")
	b.WriteString("## How signals decide\n\n")
	b.WriteString("- Two strong signals, or one strong signal and a different signal that is not a tiebreaker, " +
		"**propose** a merge. During enumeration a proposed merge is applied automatically when the session ends " +
		"(with the `amass-ai` source on every moved relationship) unless attribution is set to `journal` or `off`, " +
		"and only when its evidence includes a registry identity signal (a shared registry identifier or network " +
		"handle, or the same jurisdiction and registration number) or a shared contact record together with the " +
		"same name. A registry identifier names one legal entity; a contact record is written by whoever " +
		"registered a domain and is often reused across a parent, its subsidiaries and the firms that register " +
		"domains for them, so with only an address beside it the proposal waits for review.\n")
	b.WriteString("- One strong signal, or two signals of any strength, **needs review**: it waits in the review " +
		"journal for a person. A pair linked only by its name, with nothing against it, also needs review.\n")
	b.WriteString("- A **negative** signal lowers the score and keeps a pair from being merged automatically; without " +
		"a strong signal it also keeps the pair out of review.\n")
	b.WriteString("- A matching name is never strong: organizations in different jurisdictions often share a name and " +
		"are different companies.\n")
	b.WriteString("- A merge moves the duplicate's properties and relationships onto the organization that has more " +
		"recorded evidence, then deletes the duplicate. Fields the kept organization lacks, such as its legal name, " +
		"jurisdiction or registration number, are filled from the duplicate; a value is never replaced. The journal " +
		"records everything the merge changed, so `amass review retract -proposal <id> -reviewer <name>` restores the " +
		"duplicate and removes the relationships, properties and filled fields the merge added. A filled field that " +
		"has changed since the merge is kept.\n\n")
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
