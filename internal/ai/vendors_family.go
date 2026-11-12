// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"strings"
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

	related := map[string]bool{}
	for _, d := range f.RelatedDomains {
		related[registeredDomain(d.Domain)] = true
	}

	kept := make([]VendorUse, 0, len(r.Vendors))
	for _, v := range r.Vendors {
		in := func(set map[string]bool) bool {
			return (v.VendorID != "" && set["id:"+v.VendorID]) || set["name:"+familyKey(v.Vendor)]
		}

		switch {
		case in(own):
			r.InstitutionOwn = append(r.InstitutionOwn, v)
		case in(affiliates) || (domainName.MatchString(v.Vendor) && related[registeredDomain(v.Vendor)]):
			r.Affiliates = append(r.Affiliates, v)
		default:
			kept = append(kept, v)
		}
	}

	r.Vendors = kept
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
