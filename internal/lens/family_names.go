// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

type sameReason struct {
	why    string
	byName bool
}

// sameInstitution groups the tied organizations whose names are variants
// of each other or whose street addresses match, and returns why each
// member of the main organization's group belongs to it.
func (s *familySearch) sameInstitution(main string, ties map[string][]string) map[string]sameReason {
	ids := make([]string, 0, len(ties))
	for id := range ties {
		if !s.isUnit(s.profiles[id]) {
			ids = append(ids, id)
		}
	}

	sort.Strings(ids)

	same := map[string]sameReason{main: {why: "main", byName: true}}
	for changed := true; changed; {
		changed = false
		for _, id := range ids {
			if _, ok := same[id]; ok {
				continue
			}
			for _, other := range ids {
				if _, ok := same[other]; !ok {
					continue
				}
				if r, ok := s.sameAs(s.profiles[id], s.profiles[other]); ok {
					same[id], changed = r, true
					break
				}
			}
		}
	}

	delete(same, main)
	return same
}

// sameAs says why two organizations are one institution: a name variant,
// or else a matching street address.
func (s *familySearch) sameAs(a, b *familyProfile) (sameReason, bool) {
	for na := range a.brands {
		for nb := range b.brands {
			if na == nb {
				return sameReason{why: fmt.Sprintf("same name as %s", graph.AssetLabel(b.asset)), byName: true}, true
			}
			if nameVariant(na, nb, s.rules.GenericWords) || nameVariant(nb, na, s.rules.GenericWords) {
				return sameReason{why: fmt.Sprintf("%q is a variant of %q (%s)", na, nb, graph.AssetLabel(b.asset)),
					byName: true}, true
			}
		}
	}
	for na := range a.brands {
		for nb := range b.brands {
			if s.renamed(na, nb) {
				return sameReason{why: fmt.Sprintf("%q and %q (%s) differ only in words such as university or "+
					"college, as after a rename; not proposed for merging", na, nb, graph.AssetLabel(b.asset))}, true
			}
		}
	}
	if k := firstShared(a.addresses, b.addresses); k != "" {
		street, _, _ := strings.Cut(k, "|")
		return sameReason{why: "same street address as " + graph.AssetLabel(b.asset) + " (" + street +
			"); the address alone is not proposed for merging"}, true
	}

	return sameReason{}, false
}

// renamed reports whether two names have the same distinctive words and
// differ only in rename_words (and joining words), as Utica College and
// Utica University do after the college became a university. SUNY
// Polytechnic Institute and SUNY Polytechnic Hospital differ in a word that is not a rename
// word, so they stay apart.
func (s *familySearch) renamed(a, b string) bool {
	return renamedNames(a, b)
}

// renamedNames reports whether two organization names are the same but for
// rename words — a college that became a university — using the family rules'
// rename_words and generic_words. It is the shared, data-driven check used by
// both the family lens and the identity corrector (which must not propose
// removing a legal name that is only such a rename of a known name), and it
// compares case-insensitively.
func renamedNames(a, b string) bool {
	rules := loadFamilyRules()
	wa, wb := strings.Fields(strings.ToLower(a)), strings.Fields(strings.ToLower(b))
	stop := semantics.OrgInitialsStopWords()
	distinct := func(ws []string) map[string]bool {
		out := map[string]bool{}
		for _, w := range ws {
			if !slices.Contains(rules.GenericWords, w) {
				out[w] = true
			}
		}

		return out
	}

	da, db := distinct(wa), distinct(wb)
	if len(da) == 0 || len(da) != len(db) {
		return false
	}
	for w := range da {
		if !db[w] {
			return false
		}
	}

	rename := false
	for _, pair := range [][2][]string{{wa, wb}, {wb, wa}} {
		for _, w := range pair[0] {
			if slices.Contains(pair[1], w) {
				continue
			}
			switch {
			case slices.Contains(rules.RenameWords, w):
				rename = true
			case slices.Contains(stop, w):
			default:
				return false
			}
		}
	}

	return rename
}

// familyWords are the distinctive words of the main organization's and
// its same-institution members' names.
func (s *familySearch) familyWords(main string, same map[string]sameReason) map[string]bool {
	out := map[string]bool{}
	add := func(p *familyProfile) {
		for b := range p.brands {
			for _, w := range strings.Fields(b) {
				if len(w) >= 3 && !slices.Contains(s.rules.GenericWords, w) {
					out[w] = true
				}
			}
		}
	}

	add(s.profiles[main])
	for id, r := range same {
		if r.byName {
			add(s.profiles[id])
		}
	}

	return out
}

// sharesWord reports whether an organization's name has one of the
// family's distinctive words.
func (s *familySearch) sharesWord(p *familyProfile, words map[string]bool) bool {
	for b := range p.brands {
		for _, w := range strings.Fields(b) {
			if words[w] {
				return true
			}
		}
	}

	return false
}

// nameVariant reports whether name a is a variant of name b: its words are
// all in b, once a phrase of b may be written as its initials (SUNY for
// State University of New York), and it has a word that is not generic.
func nameVariant(a, b string, generic []string) bool {
	wa, wb := strings.Fields(a), strings.Fields(b)
	if len(wa) == 0 {
		return false
	}

	distinctive := false
	for _, w := range wa {
		if !slices.Contains(generic, w) {
			distinctive = true
			break
		}
	}
	if !distinctive {
		return false
	}

	have := map[string]bool{}
	for _, w := range wb {
		have[w] = true
	}

	// Initials skip short joining words: SUNY is State University of New
	// York.
	stop := semantics.OrgInitialsStopWords()
	for i := range wb {
		for j := i + 2; j <= len(wb); j++ {
			var all, skipped strings.Builder
			for _, w := range wb[i:j] {
				all.WriteByte(w[0])
				if !slices.Contains(stop, w) {
					skipped.WriteByte(w[0])
				}
			}

			have[all.String()] = true
			have[skipped.String()] = true
		}
	}
	for _, w := range wa {
		if !have[w] {
			return false
		}
	}

	return true
}

// isDepartment reports whether an organization's name carries a department
// or role word.
func (s *familySearch) isDepartment(p *familyProfile, domain string, words map[string]bool) bool {
	// A unit word alone is not enough: a vendor on a certificate or a
	// provider holding a network may have one in its name. A department also
	// carries the institution's name or is one of the domain's own
	// registration contacts.
	if !s.sharesWord(p, words) && !p.registers[domain] && !p.contactFor[domain] {
		return false
	}

	return s.isUnit(p)
}

// isUnit reports whether an organization is a unit: its name carries one of
// department_words, or extends another tied organization's name with words
// ending in one of unit_nouns (unitOf).
func (s *familySearch) isUnit(p *familyProfile) bool {
	if s.hasUnitWord(p) {
		return true
	}
	for id := range s.tied {
		if q := s.profiles[id]; q != p && s.unitOf(p, q) {
			return true
		}
	}

	return false
}

// unitOf reports whether p's name is q's name followed by a unit: all of
// q's words are in p's name, and p adds words, the last of them one of
// unit_nouns that q's name does not end with (a university's name and a
// medical center, an agency's name and a research center). An institution
// whose own name ends in a unit noun is not a unit of itself, because its
// other spellings add no such word.
func (s *familySearch) unitOf(p, q *familyProfile) bool {
	stop := semantics.OrgInitialsStopWords()
	for bp := range p.brands {
		wp := strings.Fields(bp)
		if len(wp) < 2 || !slices.Contains(s.rules.UnitNouns, wp[len(wp)-1]) {
			continue
		}
		for bq := range q.brands {
			wq := strings.Fields(bq)
			if bq == bp || len(wq) == 0 || wq[len(wq)-1] == wp[len(wp)-1] ||
				!nameVariant(bq, bp, s.rules.GenericWords) {
				continue
			}

			extra := 0
			for _, w := range wp {
				if !slices.Contains(wq, w) && !slices.Contains(stop, w) {
					extra++
				}
			}
			if extra > 0 {
				return true
			}
		}
	}

	return false
}

// endsInUnitNoun reports whether one of an organization's names ends in
// one of unit_nouns.
func (s *familySearch) endsInUnitNoun(p *familyProfile) bool {
	for b := range p.brands {
		if w := strings.Fields(b); len(w) > 1 && slices.Contains(s.rules.UnitNouns, w[len(w)-1]) {
			return true
		}
	}

	return false
}

// hasUnitWord reports whether an organization's name carries one of
// department_words. Such a name is never merged into the institution.
func (s *familySearch) hasUnitWord(p *familyProfile) bool {
	for _, name := range p.names {
		words := " " + strings.Join(graph.AddressWords(name), " ") + " "
		for _, d := range s.rules.DepartmentWords {
			if strings.Contains(words, " "+d+" ") {
				return true
			}
		}
	}

	return false
}
