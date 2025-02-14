// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

func (g *gleif) orgEntityToLEI(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
	if edges, err := e.Session.Cache().OutgoingEdges(orgent, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*general.Identifier); ok && id.Type == general.LEICode {
					return a
				}
			}
		}
	}
	return nil
}

func (g *gleif) leiToOrgEntity(e *et.Event, ident *dbt.Entity) *dbt.Entity {
	if edges, err := e.Session.Cache().IncomingEdges(ident, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					return a
				}
			}
		}
	}
	return nil
}

func (g *gleif) updateOrgFromLEIRecord(e *et.Event, orgent *dbt.Entity, lei *leiRecord) {
	o := orgent.Asset.(*org.Organization)

	o.LegalName = lei.Attributes.Entity.LegalName.Name
	o.FoundingDate = lei.Attributes.Entity.CreationDate
	if lei.Attributes.Entity.Status == "ACTIVE" {
		o.Active = true
	} else {
		o.Active = false
	}

	street := strings.Join(lei.Attributes.Entity.HeadquartersAddress.AddressLines, " ")
	city := lei.Attributes.Entity.HeadquartersAddress.City
	province := lei.Attributes.Entity.HeadquartersAddress.Region
	if parts := strings.Split(province, "-"); len(parts) > 1 {
		province = parts[1]
	}
	postalCode := lei.Attributes.Entity.HeadquartersAddress.PostalCode
	country := lei.Attributes.Entity.HeadquartersAddress.Country

	addr := fmt.Sprintf("%s %s %s %s %s", street, city, province, postalCode, country)
	_ = g.addAddress(e, orgent, general.SimpleRelation{Name: "location"}, addr)

	_, _ = e.Session.Cache().CreateEntity(orgent)
}

func (g *gleif) addAddress(e *et.Event, orgent *dbt.Entity, rel oam.Relation, addr string) error {
	loc := support.StreetAddressToLocation(addr)
	if loc == nil {
		return errors.New("failed to create location")
	}

	a, err := e.Session.Cache().CreateAsset(loc)
	if err != nil || a == nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", g.name, "handler", g.name))
		return err
	}

	_, _ = e.Session.Cache().CreateEntityProperty(a, &general.SourceProperty{
		Source:     g.source.Name,
		Confidence: g.source.Confidence,
	})

	edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   rel,
		FromEntity: orgent,
		ToEntity:   a,
	})
	if err != nil && edge == nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", g.name, "handler", g.name))
		return err
	}

	_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
		Source:     g.source.Name,
		Confidence: g.source.Confidence,
	})

	return nil
}
