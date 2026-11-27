// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"context"
	"slices"
	"time"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// AddOrganization adds an organization to the scope, by each of its names.
func (s *Scope) AddOrganization(o *oamorg.Organization) bool {
	return s.addEntry(o, false, true)
}

func (s *Scope) addOrganization(o *oamorg.Organization) bool {
	names := orgNameKeys(o)
	if len(names) == 0 {
		return false
	}

	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	var added bool
	for _, name := range names {
		if _, found := s.orgs[name]; !found {
			s.orgs[name] = o
			added = true
		}
	}
	return added
}

func (s *Scope) AddOrgByName(o string) bool {
	return s.AddOrganization(&oamorg.Organization{ID: o, Name: o})
}

func (s *Scope) Organizations() []*oamorg.Organization {
	set := stringset.New()
	defer set.Close()

	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	var results []*oamorg.Organization
	for _, v := range s.orgs {
		if o, valid := v.(*oamorg.Organization); valid {
			if !set.Has(o.ID) {
				set.Insert(o.ID)
				results = append(results, o)
			}
		}
	}
	return results
}

// nearMatchAccuracy is the accuracy of a match that is not exact: an
// organization name that is a misspelling of a scope organization's, or a
// street address written differently.
const nearMatchAccuracy = 90

// orgNameKeys returns the name keys (semantics.OrgNameKey) of an
// organization's name and legal name.
func orgNameKeys(o *oamorg.Organization) []string {
	var keys []string
	for _, n := range []string{o.Name, o.LegalName} {
		if k := semantics.OrgNameKey(n); k != "" {
			keys = append(keys, k)
		}
	}
	return keys
}

// orgClaimTTL is how long the names a stored organization claims are
// reused before they are read again, and orgClaimMaxEdges how many of its
// identifiers are read.
const (
	orgClaimTTL      = 2 * time.Minute
	orgClaimMaxEdges = 50
)

type orgClaimEntry struct {
	keys []string
	at   time.Time
}

// claimedNameKeys returns the name keys of the names the stored organization
// claims (Organization --id--> Identifier of the org_name or legal_name
// type), such as the acronym a merge kept when it showed the full name.
func (s *Scope) claimedNameKeys(o *oamorg.Organization) []string {
	if o.ID == "" || s.Session == nil || s.Session.DB() == nil {
		return nil
	}
	if v, ok := s.orgClaims.Load(o.ID); ok {
		if c := v.(orgClaimEntry); time.Since(c.at) < orgClaimTTL {
			return c.keys
		}
	}

	ctx, cancel := context.WithTimeout(s.Session.Ctx(), 10*time.Second)
	defer cancel()
	var keys []string
	db := s.Session.DB()
	if ents, err := db.FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 1,
		dbt.ContentFilters{"unique_id": o.ID}); err == nil && len(ents) > 0 {
		edges, _ := db.OutgoingEdges(ctx, ents[0], time.Time{}, "id")
		for i, e := range edges {
			if i >= orgClaimMaxEdges {
				break
			}
			ent, err := db.FindEntityById(ctx, e.ToEntity.ID)
			if err != nil || ent == nil {
				continue
			}
			id, ok := ent.Asset.(*oamgen.Identifier)
			if !ok || (id.Type != oamgen.OrganizationName && id.Type != oamgen.LegalName) {
				continue
			}
			if k := semantics.OrgNameKey(id.ID); k != "" && !slices.Contains(keys, k) {
				keys = append(keys, k)
			}
		}
	}
	s.orgClaims.Store(o.ID, orgClaimEntry{keys: keys, at: time.Now()})
	return keys
}

// matchesOrg returns the scope organization the organization is: the same
// name once case, punctuation and legal forms are set aside (accuracy 100),
// or a misspelling of it (nearMatchAccuracy, when that is at least conf). A
// name that only contains a scope organization's is not a match. The names
// the stored organization claims count as its names.
func (s *Scope) matchesOrg(o *oamorg.Organization, conf int) (oam.Asset, int) {
	names := orgNameKeys(o)
	for _, k := range s.claimedNameKeys(o) {
		if !slices.Contains(names, k) {
			names = append(names, k)
		}
	}
	if len(names) == 0 {
		return nil, 0
	}

	s.orgLock.Lock()
	defer s.orgLock.Unlock()

	for _, name := range names {
		if val, found := s.orgs[name]; found {
			return val, 100
		}
	}
	if nearMatchAccuracy < conf {
		return nil, 0
	}
	for n, val := range s.orgs {
		for _, name := range names {
			if _, near := semantics.OrgNameMatch(name, n); near {
				return val, nearMatchAccuracy
			}
		}
	}
	return nil, 0
}
