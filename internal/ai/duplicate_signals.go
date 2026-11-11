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
