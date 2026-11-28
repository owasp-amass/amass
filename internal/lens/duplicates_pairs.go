// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/owasp-amass/amass/v5/internal/semantics"
)

func parentChildLabels() []string {
	var out []string
	for _, s := range DuplicateSignals() {
		if s.Matcher == matchParentChild {
			out = append(out, s.Params.Labels...)
		}
	}

	return out
}

// pairs returns the organization pairs that share a name, an identifier,
// a registration, a contact record or an abbreviation. Pairs that share
// only an address are not compared.
func (s *dupSearch) pairs() [][2]string {
	buckets := map[string][]string{}
	add := func(key, id string) {
		if !slices.Contains(buckets[key], id) {
			buckets[key] = append(buckets[key], id)
		}
	}

	ids := make([]string, 0, len(s.profiles))
	for id := range s.profiles {
		ids = append(ids, id)
	}

	sort.Strings(ids)

	for _, id := range ids {
		p := s.profiles[id]
		for b := range p.brands {
			add("brand:"+b, id)
			for _, sig := range signalsOf(matchAbbreviation) {
				if a := abbreviation(b, semantics.OrgInitialsStopWords()); len(a) >= sig.Params.MinLength {
					add("brand:"+a, id)
				}
			}
		}
		for t, vals := range p.ids {
			for v := range vals {
				add("id:"+t+":"+v, id)
			}
		}
		if p.jurisdiction != "" && p.registration != "" {
			add("reg:"+p.jurisdiction+":"+p.registration, id)
		}
		for cr := range p.contacts {
			add("cr:"+cr, id)
		}
	}

	seen := map[[2]string]bool{}
	var out [][2]string
	keys := make([]string, 0, len(buckets))
	for k := range buckets {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	for _, k := range keys {
		members := buckets[k]
		if len(members) < 2 || len(members) > dupMaxBucket {
			continue
		}
		for i := 0; i < len(members); i++ {
			for j := i + 1; j < len(members); j++ {
				pair := [2]string{members[i], members[j]}
				if pair[0] > pair[1] {
					pair[0], pair[1] = pair[1], pair[0]
				}
				if !seen[pair] {
					seen[pair] = true
					out = append(out, pair)
				}
			}
		}
	}

	return out
}

func signalsOf(matcher string) []OwnershipSignal {
	var out []OwnershipSignal
	for _, s := range DuplicateSignals() {
		if s.Matcher == matcher {
			out = append(out, s)
		}
	}

	return out
}

// abbreviation returns the initials of a name of two or more words,
// skipping stop words.
func abbreviation(name string, stop []string) string {
	var b strings.Builder
	words := 0
	for _, w := range strings.Fields(name) {
		if slices.Contains(stop, w) {
			continue
		}

		r := []rune(w)
		if len(r) == 0 || !unicode.IsLetter(r[0]) {
			continue
		}

		b.WriteRune(r[0])
		words++
	}
	if words < 2 {
		return ""
	}

	return b.String()
}

// pairSignals evaluates every duplicate signal for two organizations.
func pairSignals(a, b *orgProfile) []GapSignal {
	var out []GapSignal
	add := func(def OwnershipSignal, via string) {
		out = append(out, GapSignal{Signal: def.ID, Kind: def.Kind, Via: via})
	}
	// addSupported adds a signal with the evidence it rests on: each shared
	// value is one way it holds, recorded on both organizations.
	addSupported := func(def OwnershipSignal, via string, support signalSupport) {
		out = append(out, GapSignal{Signal: def.ID, Kind: def.Kind, Via: via, support: support})
	}

	sharedBrand := firstShared(a.brands, b.brands)
	for _, def := range DuplicateSignals() {
		switch def.Matcher {
		case matchSharedIdentifier:
			if def.Params.NamesMustAgree && sharedBrand == "" {
				continue
			}
			for _, t := range def.Params.IDTypes {
				if shared := sharedKeys(a.ids[t], b.ids[t]); len(shared) > 0 {
					var support signalSupport
					for _, v := range shared {
						support = append(support, []evidenceLink{{edges: a.idEdges[t+"\x00"+v]},
							{edges: b.idEdges[t+"\x00"+v]}})
					}
					addSupported(def, t+" "+shared[0], support)
					break
				}
			}
		case matchSharedRegistration:
			if a.jurisdiction != "" && a.jurisdiction == b.jurisdiction &&
				a.registration != "" && a.registration == b.registration {
				// the organizations' own fields
				addSupported(def, a.jurisdiction+" "+a.registration, signalSupport{{
					{entities: []string{a.asset.ID}}, {entities: []string{b.asset.ID}}}})
			}
		case matchSharedContactRecord:
			if shared := sharedKeys(a.contacts, b.contacts); len(shared) > 0 {
				var support signalSupport
				for _, cr := range shared {
					support = append(support, []evidenceLink{{edges: a.contactEdges[cr]},
						{edges: b.contactEdges[cr]}})
				}
				addSupported(def, "contact record "+shared[0], support)
			}
		case matchSameBrand:
			if sharedBrand != "" {
				add(def, sharedBrand)
			}
		case matchSharedLocation:
			if loc := firstShared(a.locations, b.locations); loc != "" {
				add(def, "location "+loc)
			} else if k := firstShared(a.addresses, b.addresses); k != "" {
				street, _, _ := strings.Cut(k, "|")
				add(def, "address "+street)
			}
		case matchAbbreviation:
			if via := abbreviates(a, b, semantics.OrgInitialsStopWords(), def.Params.MinLength); via != "" {
				add(def, via)
			}
		case matchJurisdictionConflict:
			if via := jurisdictionConflict(a, b); via != "" {
				add(def, via)
			}
		case matchConflictingID:
			for _, t := range def.Params.IDTypes {
				if len(a.ids[t]) > 0 && len(b.ids[t]) > 0 && firstShared(a.ids[t], b.ids[t]) == "" {
					add(def, fmt.Sprintf("%s %s and %s", t, firstKey(a.ids[t]), firstKey(b.ids[t])))
					break
				}
			}
		case matchParentChild:
			if a.related[b.asset.ID] || b.related[a.asset.ID] {
				add(def, "linked in the corporate structure")
			} else if differentParents(a, b) {
				// offices of one name at two organizations ("Counseling")
				add(def, "units or subsidiaries of different organizations")
			} else if l := docLinkTo(a, b); l != nil && l.parent {
				// two organizations a document calls parent and unit or
				// subsidiary are not one company
				add(def, "a document states "+l.text+", in "+l.url)
			}
		case matchDocumentStatement:
			if l := docLinkTo(a, b); l != nil && l.former {
				out = append(out, GapSignal{Signal: def.ID, Kind: def.Kind, Via: l.text + ", in " + l.url,
					// a former name is history: its age takes nothing away
					Weight: DocumentWeight(false, len(l.versions), time.Time{})})
			}
		}
	}

	return out
}

// differentParents reports whether two organizations are each a unit or
// subsidiary of a parent, and share none.
func differentParents(a, b *orgProfile) bool {
	if len(a.parents) == 0 || len(b.parents) == 0 {
		return false
	}
	return firstShared(a.parents, b.parents) == ""
}

// jurisdictionConflict describes how two organizations' registrations
// disagree: different countries, or one jurisdiction and two registration
// numbers.
func jurisdictionConflict(a, b *orgProfile) string {
	if a.jurisdiction == "" || b.jurisdiction == "" {
		return ""
	}

	ca, _, _ := strings.Cut(a.jurisdiction, "-")
	cb, _, _ := strings.Cut(b.jurisdiction, "-")
	switch {
	case ca != cb:
		return a.jurisdiction + " and " + b.jurisdiction
	case a.jurisdiction == b.jurisdiction && a.registration != "" && b.registration != "" &&
		a.registration != b.registration:
		return fmt.Sprintf("%s registrations %s and %s", a.jurisdiction, a.registration, b.registration)
	}

	return ""
}

func abbreviates(a, b *orgProfile, stop []string, minLen int) string {
	check := func(x, y *orgProfile) string {
		for long := range x.brands {
			abbr := abbreviation(long, stop)
			if len(abbr) < minLen {
				continue
			}
			for short := range y.brands {
				if short == abbr {
					return short + " = " + long
				}
			}
		}

		return ""
	}
	if v := check(a, b); v != "" {
		return v
	}

	return check(b, a)
}

func firstShared(a, b map[string]bool) string {
	if shared := sharedKeys(a, b); len(shared) > 0 {
		return shared[0]
	}
	return ""
}

// sharedKeys returns the keys a and b share, sorted.
func sharedKeys(a, b map[string]bool) []string {
	var shared []string
	for k := range a {
		if b[k] {
			shared = append(shared, k)
		}
	}
	sort.Strings(shared)
	return shared
}

func firstKey(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}

	sort.Strings(keys)
	if len(keys) == 0 {
		return ""
	}

	return keys[0]
}

// chooseSurvivor keeps the organization with more recorded evidence, then
// the one with a registry identity, then the older one.
func chooseSurvivor(a, b *orgProfile) (*orgProfile, *orgProfile) {
	rank := func(p *orgProfile) []int {
		registered := 0
		if p.jurisdiction != "" || len(p.ids["lei"]) > 0 {
			registered = 1
		}

		id, _ := strconv.Atoi(p.asset.ID)
		return []int{p.evidence, registered, -id}
	}

	if slices.Compare(rank(a), rank(b)) >= 0 {
		return a, b
	}

	return b, a
}
