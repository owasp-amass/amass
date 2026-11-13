// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// applyFamily takes the domain's own institution out of the vendor list
// and sets its affiliates apart. A domain with no documented owner has no
// footprint beyond its own names, so the organizations holding the
// institution's networks, and the domains its networks also serve, would
// otherwise be listed as its vendors. The family lens decides which
// organizations are the institution (same institution or department) and
// which are affiliates; nothing is written to the database.
func applyFamily(r *ThirdPartyReport, f FamilyReport) {
	if f.Main == nil {
		return
	}

	r.Institution = assetLabel(*f.Main)
	own, affiliates := map[string]bool{}, map[string]bool{}
	mark := func(set map[string]bool, a Asset) {
		set["id:"+a.ID] = true
		set["name:"+familyKey(assetLabel(a))] = true
	}

	mark(own, *f.Main)
	for _, m := range f.Members {
		switch m.Relation {
		case FamilySame, FamilyDepartment:
			mark(own, m.Organization)
		case FamilyAffiliate:
			mark(affiliates, m.Organization)
		}
	}

	words := familyNameWords(f)
	related, ownRelated := map[string]bool{}, map[string]bool{}
	for _, d := range f.RelatedDomains {
		related[registeredDomain(d.Domain)] = true
		if d.Own {
			ownRelated[registeredDomain(d.Domain)] = true
		}
	}

	kept := make([]VendorUse, 0, len(r.Vendors))
	for _, v := range r.Vendors {
		in := func(set map[string]bool) bool {
			return (v.VendorID != "" && set["id:"+v.VendorID]) || set["name:"+familyKey(v.Vendor)]
		}

		isDomain := domainName.MatchString(v.Vendor)
		switch {
		case in(own) || ownLabel(v.Vendor, words) || (isDomain && familyDomain(f, v.Vendor)) ||
			(isDomain && ownRelated[registeredDomain(v.Vendor)]) ||
			(!isDomain && institutionName(f, v.Vendor)):
			r.InstitutionOwn = append(r.InstitutionOwn, v)
		case in(affiliates) || (isDomain && related[registeredDomain(v.Vendor)]) ||
			(!isDomain && initialsOfFamilyWord(v.Vendor, words)):
			r.Affiliates = append(r.Affiliates, v)
		default:
			kept = append(kept, v)
		}
	}

	r.Vendors = kept
}

// familyNameWords are the distinctive words, of four letters or more, in
// the names of the main organization and the members whose names are
// variants of it.
func familyNameWords(f FamilyReport) map[string]bool {
	generic := loadFamilyRules().GenericWords
	out := map[string]bool{}
	add := func(a Asset) {
		for _, name := range []string{contentString(a, "name"), contentString(a, "legal_name"), assetLabel(a)} {
			for _, w := range addressWords(name) {
				if len(w) >= 4 && !slices.Contains(generic, w) {
					out[w] = true
				}
			}
		}
	}

	if f.Main != nil {
		add(*f.Main)
	}
	for _, m := range f.Members {
		if m.Relation == FamilySame && m.ByName {
			add(m.Organization)
		}
	}
	return out
}

// ownLabel reports whether a party's name is a registry label of the
// institution's: one word with no spaces, such as a network name
// (GRUMMAN1, UK_NORTHROP), one of whose letter runs is a distinctive word
// of the institution's name. An organization's name has spaces or is a word
// on its own, so it is never taken for a label.
func ownLabel(name string, words map[string]bool) bool {
	if name == "" || strings.ContainsAny(name, " \t") || domainName.MatchString(name) {
		return false
	}

	runs := strings.FieldsFunc(strings.ToLower(name), func(r rune) bool { return !unicode.IsLetter(r) })
	if len(runs) == 1 && runs[0] == strings.ToLower(name) {
		// A plain word is an organization's name, not a label.
		return false
	}
	for _, r := range runs {
		if words[r] {
			return true
		}
	}
	return false
}

// familyDomain reports whether a domain is the institution's: one whose
// label spells the name of the main organization or of a member counted as
// the institution (automattic.com for Automattic), by the family lens's
// nameMatchesLabel.
func familyDomain(f FamilyReport, domain string) bool {
	return familyDomainOf(f, domain, false)
}

// relatedDomain reports whether a domain is the institution's or an
// affiliate's: familyDomain, a domain the family's dedicated networks also
// serve, or one whose label spells an affiliate's name.
func relatedDomain(f FamilyReport, domain string) bool {
	rd := registeredDomain(strings.ToLower(domain))
	for _, d := range f.RelatedDomains {
		if registeredDomain(d.Domain) == rd {
			return true
		}
	}
	return familyDomainOf(f, domain, true)
}

func familyDomainOf(f FamilyReport, domain string, affiliates bool) bool {
	label := domainLabel(strings.ToLower(domain))
	if label == "" || f.Main == nil {
		return false
	}

	rules := loadFamilyRules()
	stop := abbreviationStopWords()
	match := func(a Asset) bool {
		for _, name := range []string{contentString(a, "name"), contentString(a, "legal_name"), assetLabel(a)} {
			if name != "" && nameMatchesLabel(addressWords(name), label, rules.GenericWords, stop) {
				return true
			}
		}
		return false
	}

	if match(*f.Main) {
		return true
	}
	for _, m := range f.Members {
		member := m.Relation == FamilySame || m.Relation == FamilyDepartment ||
			(affiliates && m.Relation == FamilyAffiliate)
		if member && match(m.Organization) {
			return true
		}
	}
	return false
}

// institutionName reports whether a party's name is another name of the
// institution: the domain's label spells it (tumblr for tumblr.com), or it
// is a variant of the main organization's or a same-institution member's
// name (National Grid for National Grid USA Service Company), as the family
// lens compares names.
func institutionName(f FamilyReport, name string) bool {
	rules := loadFamilyRules()
	stop := abbreviationStopWords()
	b := brandName(name)
	if b == "" {
		return false
	}
	if label := domainLabel(f.Domain); label != "" && nameMatchesLabel(strings.Fields(b), label,
		rules.GenericWords, stop) {
		return true
	}

	match := func(a Asset) bool {
		for _, n := range []string{contentString(a, "name"), contentString(a, "legal_name"), assetLabel(a)} {
			if o := brandName(n); o != "" && (o == b || nameVariant(b, o, rules.GenericWords) ||
				nameVariant(o, b, rules.GenericWords)) {
				return true
			}
		}
		return false
	}
	if f.Main != nil && match(*f.Main) {
		return true
	}
	for _, m := range f.Members {
		if m.Relation == FamilySame && m.ByName && match(m.Organization) {
			return true
		}
	}
	return false
}

// initialsOfFamilyWord reports whether a party's initials are a word of the
// institution's name: the State University of New York for SUNY - Mohawk
// Valley Community College, a system the institution belongs to.
func initialsOfFamilyWord(name string, words map[string]bool) bool {
	a := abbreviation(brandName(name), abbreviationStopWords())
	return len(a) >= 3 && words[a]
}

// familyKey compares an organization's names across sources, where one
// may carry a leading article ("The Johns Hopkins University").
func familyKey(name string) string {
	name = strings.TrimSpace(name)
	if len(name) > 4 && strings.EqualFold(name[:4], "the ") {
		name = name[4:]
	}

	return partyKey(name)
}

// familyLines renders what applyFamily set apart from the vendors.
func familyLines(r ThirdPartyReport) string {
	if r.Institution == "" && r.FamilyNote == "" {
		return ""
	}

	var b strings.Builder
	if r.FamilyNote != "" {
		fmt.Fprintf(&b, "\n%s\n", r.FamilyNote)
	}
	if r.Institution == "" {
		return b.String()
	}

	fmt.Fprintf(&b, "\nThe family lens ties %s to %s; the institution and its affiliates are not vendors.\n",
		assetLabel(r.Root), r.Institution)
	list := func(title string, uses []VendorUse) {
		if len(uses) == 0 {
			return
		}

		parts := make([]string, 0, len(uses))
		for _, u := range uses {
			parts = append(parts, fmt.Sprintf("%s (%d asset(s), %s)", u.Vendor, u.Assets, u.Kind))
		}
		fmt.Fprintf(&b, "%s: %s\n", title, strings.Join(parts, "; "))
	}

	list("The institution's own", r.InstitutionOwn)
	list("Affiliated organizations and domains", r.Affiliates)
	return b.String()
}
