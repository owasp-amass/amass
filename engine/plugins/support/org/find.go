// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"context"
	"errors"
	"time"

	"github.com/caffix/stringset"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func dedupChecks(sess et.Session, obj *dbt.Entity, o *oamorg.Organization) *dbt.Entity {
	var names []string

	for _, name := range []string{o.Name, o.LegalName} {
		if name != "" {
			names = append(names, name)
		}
	}
	if len(names) == 0 {
		return nil
	}

	switch obj.Asset.(type) {
	case *oamcon.ContactRecord:
		if org, found := nameExistsInContactRecord(sess, obj, names); found {
			return org
		}
		if org, err := existsAndSharesLocEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndSharesAncestorEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndHasAncestorInSession(sess, o); err == nil {
			return org
		}
	case *oamorg.Organization:
		if org, found := nameRelatedToOrganization(sess, obj, names); found {
			return org
		}
		if org, err := existsAndSharesLocEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndSharesAncestorEntity(sess, obj, o); err == nil {
			return org
		}
		if org, err := existsAndHasAncestorInSession(sess, o); err == nil {
			return org
		}
	}

	if org, found := nameExistsInSessionScope(sess, o); found {
		return org
	}

	return nil
}

func nameExistsInContactRecord(sess et.Session, cr *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if cr == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(sess, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func nameExistsInSessionScope(sess et.Session, o *oamorg.Organization) (*dbt.Entity, bool) {
	ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
	defer cancel()

	ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Organization, time.Time{}, 0, dbt.ContentFilters{
		"name": o.Name,
	})
	if err != nil || len(ents) == 0 {
		return nil, false
	}

	for _, ent := range ents {
		if _, err := sess.Scope().IsAssociated(&et.Association{Submission: ent}); err == nil {
			return ent, true
		}
	}

	return nil, false
}

func nameRelatedToOrganization(sess et.Session, orgent *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if orgent == nil {
		return nil, false
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := sess.DB().IncomingEdges(ctx, orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(sess, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	if edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(sess, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func existsAndSharesLocEntity(sess et.Session, obj *dbt.Entity, o *oamorg.Organization) (*dbt.Entity, error) {
	var names []string
	var locs []*dbt.Entity

	if o.Name != "" {
		names = append(names, o.Name)
	}
	if o.LegalName != "" {
		names = append(names, o.LegalName)
	}
	if len(names) == 0 {
		return nil, errors.New("zero names provided in the Organization")
	}

	ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := sess.DB().OutgoingEdges(ctx, obj, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
		for _, edge := range edges {
			if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamcon.Location); ok {
					locs = append(locs, a)
				}
			}
		}
	}

	// get all locations that match the ones discovered on the graph
	locs = append(locs, matchingLocations(sess, locs)...)

	var orgents, crecords []*dbt.Entity
	for _, loc := range locs {
		if edges, err := sess.DB().IncomingEdges(ctx, loc, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
			for _, edge := range edges {
				if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oamcon.ContactRecord); ok && a.ID != obj.ID {
						crecords = append(crecords, a)
					} else if _, ok := a.Asset.(*oamorg.Organization); ok && a.ID != obj.ID {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, cr := range crecords {
		if edges, err := sess.DB().OutgoingEdges(ctx, cr, time.Time{}, "organization"); err == nil {
			for _, edge := range edges {
				if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oamorg.Organization); ok {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, orgent := range orgents {
		if _, _, found := NameMatch(sess, orgent, names); found {
			return orgent, nil
		}
	}

	return nil, errors.New("no matching org found")
}

func matchingLocations(sess et.Session, locs []*dbt.Entity) []*dbt.Entity {
	var newlocs []*dbt.Entity

	set := stringset.New()
	defer set.Close()

	for _, loc := range locs {
		set.Insert(loc.ID)
	}

	for _, loc := range locs {
		lasset, valid := loc.Asset.(*oamcon.Location)
		if !valid {
			continue
		}

		cf := make(dbt.ContentFilters)
		if lasset.BuildingNumber != "" {
			cf["building_number"] = lasset.BuildingNumber
		}
		if lasset.StreetName != "" {
			cf["street_name"] = lasset.StreetName
		}
		if lasset.City != "" {
			cf["city"] = lasset.City
		}
		if lasset.Province != "" {
			cf["province"] = lasset.Province
		}
		if lasset.Country != "" {
			cf["country"] = lasset.Country
		}

		ctx, cancel := context.WithTimeout(sess.Ctx(), 10*time.Second)
		defer cancel()

		ents, err := sess.DB().FindEntitiesByContent(ctx, oam.Location, time.Time{}, 0, cf)
		if err != nil || len(ents) == 0 {
			continue
		}

		for _, ent := range ents {
			if !set.Has(ent.ID) {
				set.Insert(ent.ID)
				newlocs = append(newlocs, ent)
			}
		}
	}

	return newlocs
}

func existsAndSharesAncestorEntity(sess et.Session, obj *dbt.Entity, o *oamorg.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(sess, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}

	assets := []*dbt.Entity{obj}
	ancestors := make(map[string]struct{})
	ancestors[obj.ID] = struct{}{}
	for i := 0; i < 10 && len(assets) > 0; i++ {
		remaining := assets
		assets = []*dbt.Entity{}

		ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
		defer cancel()

		for _, r := range remaining {
			if edges, err := sess.DB().IncomingEdges(ctx, r, time.Time{}); err == nil {
				for _, edge := range edges {
					if a, err := sess.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
						if _, found := ancestors[a.ID]; !found {
							ancestors[a.ID] = struct{}{}
							assets = append(assets, a)
						}
					}
				}
			}
		}
	}

	visited := make(map[string]struct{})
	for _, orgent := range orgents {
		assets = []*dbt.Entity{orgent}

		for i := 0; i < 10 && len(assets) > 0; i++ {
			remaining := assets
			assets = []*dbt.Entity{}

			for _, r := range remaining {
				ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
				defer cancel()

				if edges, err := sess.DB().IncomingEdges(ctx, r, time.Time{}); err == nil {
					for _, edge := range edges {
						id := edge.FromEntity.ID
						if _, found := visited[id]; found {
							continue
						}
						visited[id] = struct{}{}

						if a, err := sess.DB().FindEntityById(ctx, id); err == nil && a != nil {
							if _, found := ancestors[a.ID]; !found {
								assets = append(assets, a)
							} else {
								return orgent, nil
							}
						}
					}
				}
			}
		}
	}

	return nil, errors.New("no matching org found")
}

func existsAndHasAncestorInSession(sess et.Session, o *oamorg.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(sess, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}

	visited := make(map[string]struct{})
	for _, orgent := range orgents {
		if sess.Backlog().Has(orgent) {
			return orgent, nil
		}

		assets := []*dbt.Entity{orgent}
		for i := 0; i < 10 && len(assets) > 0; i++ {
			remaining := assets
			assets = []*dbt.Entity{}

			for _, r := range remaining {
				ctx, cancel := context.WithTimeout(sess.Ctx(), 30*time.Second)
				defer cancel()

				if edges, err := sess.DB().IncomingEdges(ctx, r, time.Time{}); err == nil {
					for _, edge := range edges {
						id := edge.FromEntity.ID
						if _, found := visited[id]; found {
							continue
						}
						visited[id] = struct{}{}

						if a, err := sess.DB().FindEntityById(ctx, id); err == nil && a != nil {
							if sess.Backlog().Has(edge.FromEntity) {
								return orgent, nil
							}
							assets = append(assets, a)
						}
					}
				}
			}
		}
	}

	return nil, errors.New("no matching org found")
}
