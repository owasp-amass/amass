// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func (g *gleif) orgEntityToLEI(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := e.Session.DB().OutgoingEdges(ctx, orgent, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*oamgen.Identifier); ok && id.Type == oamgen.LEICode {
					return a
				}
			}
		}
	}
	return nil
}

func (g *gleif) updateOrgFromLEIRecord(e *et.Event, orgent *dbt.Entity, lei *LEIRecord, conf int) {
	o := orgent.Asset.(*oamorg.Organization)

	// check if the org entity already has a LEI identifier
	if leient := g.orgEntityToLEI(e, orgent); leient != nil {
		// check if the LEI identifier is the same as the one we are processing
		if id, ok := leient.Asset.(*oamgen.Identifier); ok && id.ID != lei.ID {
			return
		}
	}

	if _, err := g.createLEIFromRecord(e, orgent, lei, conf); err != nil {
		msg := fmt.Sprintf("failed to create the LEI Identifier from the record: %s", err.Error())
		e.Session.Log().Error(msg, slog.Group("plugin", "name", g.name, "handler", g.name))
	}

	if lname := lei.Attributes.Entity.LegalName.Name; lname != "" {
		o.LegalName = strings.ToLower(lname)
		_ = g.addIdentifiersToOrg(e, orgent, oamgen.LegalName, []string{lname}, conf)
	}

	var otherNames []string
	for _, other := range lei.Attributes.Entity.OtherNames {
		otherNames = append(otherNames, strings.ToLower(other.Name))
	}
	for _, other := range lei.Attributes.Entity.TransliteratedOtherNames {
		otherNames = append(otherNames, strings.ToLower(other.Name))
	}
	_ = g.addIdentifiersToOrg(e, orgent, oamgen.OrganizationName, otherNames, conf)

	o.Jurisdiction = lei.Attributes.Entity.Jurisdiction
	o.RegistrationID = lei.Attributes.Entity.RegisteredAs
	if o.RegistrationID != "" {
		_, _ = org.CreateOrgRegistrationIDClaim(e.Session, orgent, o.RegistrationID, g.source)
	}

	o.FoundingDate = lei.Attributes.Entity.CreationDate
	if lei.Attributes.Entity.Status == "ACTIVE" {
		o.Active = true
	} else {
		o.Active = false
	}

	addr := g.buildAddrFromLEIAddress(&lei.Attributes.Entity.LegalAddress)
	_ = g.addAddress(e, orgent, oamgen.SimpleRelation{Name: "legal_address"}, addr, conf)

	addr = g.buildAddrFromLEIAddress(&lei.Attributes.Entity.HeadquartersAddress)
	_ = g.addAddress(e, orgent, oamgen.SimpleRelation{Name: "hq_address"}, addr, conf)

	for _, a := range lei.Attributes.Entity.OtherAddresses {
		addr = g.buildAddrFromLEIAddress(&a)
		_ = g.addAddress(e, orgent, oamgen.SimpleRelation{Name: "location"}, addr, conf)
	}

	_ = g.addIdentifiersToOrg(e, orgent, oamgen.BankIDCode, lei.Attributes.BIC, conf)
	_ = g.addIdentifiersToOrg(e, orgent, oamgen.MarketIDCode, lei.Attributes.MIC, conf)
	_ = g.addIdentifiersToOrg(e, orgent, oamgen.OpenCorpID, []string{lei.Attributes.OCID}, conf)
	_ = g.addIdentifiersToOrg(e, orgent, oamgen.SPGlobalCompanyID, lei.Attributes.SPGlobal, conf)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	// update the Organization
	if _, err := e.Session.DB().CreateEntity(ctx, orgent); err != nil {
		msg := fmt.Sprintf("failed to update the Organization asset for %s: %s", o.Name, err)
		e.Session.Log().Error(msg, slog.Group("plugin", "name", g.name, "handler", g.name))
	}
}

func (g *gleif) addAddress(e *et.Event, orgent *dbt.Entity, rel oam.Relation, addr string, conf int) error {
	loc := support.StreetAddressToLocation(addr)
	if loc == nil {
		return errors.New("failed to create location")
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	a, err := e.Session.DB().CreateAsset(ctx, loc)
	if err != nil || a == nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", g.name, "handler", g.name))
		return err
	}

	_, _ = e.Session.DB().CreateEntityProperty(ctx, a, &oamgen.SourceProperty{
		Source:     g.source.Name,
		Confidence: conf,
	})

	if err := g.createRelation(ctx, e.Session, orgent, rel, a, conf); err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", g.name, "handler", g.name))
		return err
	}
	return nil
}

func (g *gleif) addIdentifiersToOrg(e *et.Event, orgent *dbt.Entity, idtype string, ids []string, conf int) error {
	seconds := 10 * len(ids)
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), time.Duration(seconds)*time.Second)
	defer cancel()

	for _, id := range ids {
		if id == "" {
			continue
		}

		oamid := &oamgen.Identifier{
			UniqueID: fmt.Sprintf("%s:%s", idtype, id),
			ID:       id,
			Type:     idtype,
		}

		ident, err := e.Session.DB().CreateAsset(ctx, oamid)
		if err != nil || ident == nil {
			return err
		}

		_, _ = e.Session.DB().CreateEntityProperty(ctx, ident, &oamgen.SourceProperty{
			Source:     g.source.Name,
			Confidence: conf,
		})

		if err := g.createRelation(ctx, e.Session, orgent, oamgen.SimpleRelation{Name: "id"}, ident, conf); err != nil {
			return err
		}
	}

	return nil
}
