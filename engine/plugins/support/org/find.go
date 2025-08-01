// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package org

import (
	"errors"
	"time"

	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func dedupChecks(session et.Session, obj *dbt.Entity, o *oamorg.Organization) *dbt.Entity {
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
	case *contact.ContactRecord:
		if org, found := nameExistsInContactRecord(session, obj, names); found {
			return org
		}
		if org, err := existsAndSharesLocEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := existsAndSharesAncestorEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := existsAndHasAncestorInSession(session, o); err == nil {
			return org
		}
	case *oamorg.Organization:
		if org, found := nameRelatedToOrganization(session, obj, names); found {
			return org
		}
		if org, err := existsAndSharesLocEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := existsAndSharesAncestorEntity(session, obj, o); err == nil {
			return org
		}
		if org, err := existsAndHasAncestorInSession(session, o); err == nil {
			return org
		}
	}

	return nil
}

func nameExistsInContactRecord(session et.Session, cr *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if cr == nil {
		return nil, false
	}

	if edges, err := session.Cache().OutgoingEdges(cr, time.Time{}, "organization"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(session, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func nameRelatedToOrganization(session et.Session, orgent *dbt.Entity, names []string) (*dbt.Entity, bool) {
	if orgent == nil {
		return nil, false
	}

	if edges, err := session.Cache().IncomingEdges(orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(session, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	if edges, err := session.Cache().OutgoingEdges(orgent, time.Time{}, "subsidiary"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					if _, _, found := NameMatch(session, a, names); found {
						return a, true
					}
				}
			}
		}
	}
	return nil, false
}

func existsAndSharesLocEntity(session et.Session, obj *dbt.Entity, o *oamorg.Organization) (*dbt.Entity, error) {
	var locs []*dbt.Entity

	if edges, err := session.Cache().OutgoingEdges(obj, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
		for _, edge := range edges {
			if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*contact.Location); ok {
					locs = append(locs, a)
				}
			}
		}
	}

	var orgents, crecords []*dbt.Entity
	for _, loc := range locs {
		if edges, err := session.Cache().IncomingEdges(loc, time.Time{}, "legal_address", "hq_address", "location"); err == nil {
			for _, edge := range edges {
				if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*contact.ContactRecord); ok && a.ID != obj.ID {
						crecords = append(crecords, a)
					} else if _, ok := a.Asset.(*oamorg.Organization); ok && a.ID != obj.ID {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, cr := range crecords {
		if edges, err := session.Cache().OutgoingEdges(cr, time.Time{}, "organization"); err == nil {
			for _, edge := range edges {
				if a, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
					if _, ok := a.Asset.(*oamorg.Organization); ok {
						orgents = append(orgents, a)
					}
				}
			}
		}
	}

	for _, orgent := range orgents {
		if _, _, found := NameMatch(session, orgent, []string{o.Name, o.LegalName}); found {
			return orgent, nil
		}
	}

	return nil, errors.New("no matching org found")
}

func existsAndSharesAncestorEntity(session et.Session, obj *dbt.Entity, o *oamorg.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(session, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}

	assets := []*dbt.Entity{obj}
	ancestors := make(map[string]struct{})
	ancestors[obj.ID] = struct{}{}
	for i := 0; i < 10 && len(assets) > 0; i++ {
		remaining := assets
		assets = []*dbt.Entity{}

		for _, r := range remaining {
			if edges, err := session.Cache().IncomingEdges(r, time.Time{}); err == nil {
				for _, edge := range edges {
					if a, err := session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
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
				if edges, err := session.Cache().IncomingEdges(r, time.Time{}); err == nil {
					for _, edge := range edges {
						id := edge.FromEntity.ID
						if _, found := visited[id]; found {
							continue
						}
						visited[id] = struct{}{}

						if a, err := session.Cache().FindEntityById(id); err == nil && a != nil {
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

func existsAndHasAncestorInSession(session et.Session, o *oamorg.Organization) (*dbt.Entity, error) {
	orgents, err := orgsWithSameNames(session, []string{o.Name, o.LegalName})
	if err != nil {
		return nil, err
	}

	visited := make(map[string]struct{})
	for _, orgent := range orgents {
		assets := []*dbt.Entity{orgent}

		for i := 0; i < 10 && len(assets) > 0; i++ {
			remaining := assets
			assets = []*dbt.Entity{}

			for _, r := range remaining {
				if edges, err := session.Cache().IncomingEdges(r, time.Time{}); err == nil {
					for _, edge := range edges {
						id := edge.FromEntity.ID
						if _, found := visited[id]; found {
							continue
						}
						visited[id] = struct{}{}

						if a, err := session.Cache().FindEntityById(id); err == nil && a != nil {
							if session.Queue().Has(edge.FromEntity) {
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
