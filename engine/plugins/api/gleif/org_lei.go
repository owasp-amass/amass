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

func (g *gleif) updateOrgFromLEIRecord(e *et.Event, orgent *dbt.Entity, lei *leiRecord, conf int) {
	o := orgent.Asset.(*org.Organization)

	// check if the org entity already has a LEI identifier
	if leient := g.orgEntityToLEI(e, orgent); leient != nil {
		// check if the LEI identifier is the same as the one we are processing
		if id, ok := leient.Asset.(*general.Identifier); ok && id.ID != lei.ID {
			return
		}
	}

	if _, err := g.createLEIFromRecord(e, orgent, lei, conf); err != nil {
		msg := fmt.Sprintf("failed to create the LEI Identifier from the record: %s", err.Error())
		e.Session.Log().Error(msg, slog.Group("plugin", "name", g.name, "handler", g.name))
	}

	o.LegalName = strings.ToLower(lei.Attributes.Entity.LegalName.Name)
	if o.LegalName != "" {
		_ = g.addIdentifiersToOrg(e, orgent, general.LegalName, []string{o.LegalName}, conf)
	}

	var otherNames []string
	for _, other := range lei.Attributes.Entity.OtherNames {
		otherNames = append(otherNames, strings.ToLower(other.Name))
	}
	for _, other := range lei.Attributes.Entity.TransliteratedOtherNames {
		otherNames = append(otherNames, strings.ToLower(other.Name))
	}
	_ = g.addIdentifiersToOrg(e, orgent, general.OrganizationName, otherNames, conf)

	o.FoundingDate = lei.Attributes.Entity.CreationDate
	o.Jurisdiction = lei.Attributes.Entity.Jurisdiction
	o.RegistrationID = lei.Attributes.Entity.RegisteredAs
	if lei.Attributes.Entity.Status == "ACTIVE" {
		o.Active = true
	} else {
		o.Active = false
	}

	addr := g.buildAddrFromLEIAddress(&lei.Attributes.Entity.LegalAddress)
	_ = g.addAddress(e, orgent, general.SimpleRelation{Name: "legal_address"}, addr, conf)

	addr = g.buildAddrFromLEIAddress(&lei.Attributes.Entity.HeadquartersAddress)
	_ = g.addAddress(e, orgent, general.SimpleRelation{Name: "hq_address"}, addr, conf)

	for _, a := range lei.Attributes.Entity.OtherAddresses {
		addr = g.buildAddrFromLEIAddress(&a)
		_ = g.addAddress(e, orgent, general.SimpleRelation{Name: "location"}, addr, conf)
	}

	_ = g.addIdentifiersToOrg(e, orgent, general.BankIDCode, lei.Attributes.BIC, conf)
	_ = g.addIdentifiersToOrg(e, orgent, general.MarketIDCode, lei.Attributes.MIC, conf)
	_ = g.addIdentifiersToOrg(e, orgent, general.OpenCorpID, []string{lei.Attributes.OCID}, conf)
	_ = g.addIdentifiersToOrg(e, orgent, general.SPGlobalCompanyID, lei.Attributes.SPGlobal, conf)
	_, _ = e.Session.Cache().CreateEntity(orgent)
}

func (g *gleif) addAddress(e *et.Event, orgent *dbt.Entity, rel oam.Relation, addr string, conf int) error {
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
		Confidence: conf,
	})

	if err := g.createRelation(e.Session, orgent, rel, a, conf); err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", g.name, "handler", g.name))
		return err
	}

	return nil
}

func (g *gleif) addIdentifiersToOrg(e *et.Event, orgent *dbt.Entity, idtype string, ids []string, conf int) error {
	for _, id := range ids {
		if id == "" {
			continue
		}

		oamid := &general.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", idtype, id),
			ID:       id,
			Type:     idtype,
		}

		ident, err := e.Session.Cache().CreateAsset(oamid)
		if err != nil || ident == nil {
			return err
		}

		_, _ = e.Session.Cache().CreateEntityProperty(ident, &general.SourceProperty{
			Source:     g.source.Name,
			Confidence: conf,
		})

		if err := g.createRelation(e.Session, orgent, general.SimpleRelation{Name: "id"}, ident, conf); err != nil {
			return err
		}
	}

	return nil
}
