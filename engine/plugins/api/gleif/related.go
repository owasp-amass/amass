// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type relatedOrgs struct {
	name   string
	plugin *gleif
}

func (ro *relatedOrgs) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*oamgen.Identifier)
	if !ok {
		return errors.New("failed to cast the Identifier asset")
	} else if ident.Type != oamgen.LEICode {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Identifier), string(oam.Identifier), ro.plugin.name)
	if err != nil {
		return err
	}

	var orgs []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, ro.plugin.source, since) {
		orgs = append(orgs, ro.lookup(e, e.Entity, since)...)
	} else {
		orgs = append(orgs, ro.query(e, e.Entity)...)
		support.MarkAssetMonitored(e.Session, e.Entity, ro.plugin.source)
	}

	if len(orgs) > 0 {
		ro.process(e, orgs)
	}
	return nil
}

func (ro *relatedOrgs) lookup(e *et.Event, ident *dbt.Entity, since time.Time) []*dbt.Entity {
	var o *dbt.Entity

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Minute)
	defer cancel()

	if edges, err := e.Session.DB().IncomingEdges(ctx, ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, ro.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					o = a
					break
				}
			}
		}
	}

	if o == nil {
		return nil
	}

	var p *dbt.Entity
	if edges, err := e.Session.DB().IncomingEdges(ctx, o, since, "subsidiary"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, ro.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					p = a
					break
				}
			}
		}
	}

	var children []*dbt.Entity
	if edges, err := e.Session.DB().OutgoingEdges(ctx, o, since, "subsidiary"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.DB().FindEdgeTags(ctx, edge, since, ro.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*oamorg.Organization); ok {
					children = append(children, a)
				}
			}
		}
	}

	var results []*dbt.Entity
	for _, ent := range append([]*dbt.Entity{o, p}, children...) {
		if ent != nil {
			results = append(results, ent)
		}
	}
	return results
}

func (ro *relatedOrgs) query(e *et.Event, ident *dbt.Entity) []*dbt.Entity {
	id := ident.Asset.(*oamgen.Identifier)
	parent, _ := GLEIFGetDirectParentRecord(e.Session.Ctx(), id.ID)
	children, _ := GLEIFGetDirectChildrenRecords(e.Session.Ctx(), id.ID)
	return ro.store(e, ident, parent, children)
}

func (ro *relatedOrgs) store(e *et.Event, ident *dbt.Entity, parent *LEIRecord, children []*LEIRecord) []*dbt.Entity {
	var orgs []*dbt.Entity
	id := ident.Asset.(*oamgen.Identifier)

	orgent, err := org.FindOrgByLEICode(e.Session, id.ID, ro.plugin.source)
	if err != nil || orgent == nil {
		return orgs
	}
	orgs = append(orgs, orgent)

	if parent != nil {
		parentorg := &oamorg.Organization{
			Name:           parent.Attributes.Entity.LegalName.Name,
			Jurisdiction:   parent.Attributes.Entity.Jurisdiction,
			RegistrationID: parent.Attributes.Entity.RegisteredAs,
		}

		if parentent, err := ro.getOrganization(e.Session, orgent, nil, parentorg, parent.ID); err == nil {
			orgs = append(orgs, parentent)
			ro.plugin.updateOrgFromLEIRecord(e, parentent, parent, ro.plugin.source.Confidence)
			support.MarkAssetMonitored(e.Session, parentent, ro.plugin.source)
			_ = ro.plugin.createRelation(e.Session.Ctx(), e.Session, parentent,
				&oamgen.SimpleRelation{Name: "subsidiary"}, orgent, ro.plugin.source.Confidence)
		}
	}

	for _, child := range children {
		childorg := &oamorg.Organization{
			Name:           child.Attributes.Entity.LegalName.Name,
			Jurisdiction:   child.Attributes.Entity.Jurisdiction,
			RegistrationID: child.Attributes.Entity.RegisteredAs,
		}

		if childent, err := ro.getOrganization(e.Session, orgent,
			&oamgen.SimpleRelation{Name: "subsidiary"}, childorg, child.ID); err == nil {
			orgs = append(orgs, childent)
			ro.plugin.updateOrgFromLEIRecord(e, childent, child, ro.plugin.source.Confidence)
			support.MarkAssetMonitored(e.Session, childent, ro.plugin.source)
		}
	}

	return orgs
}

func (ro *relatedOrgs) getOrganization(sess et.Session, ent *dbt.Entity, rel oam.Relation, o *oamorg.Organization, lei string) (*dbt.Entity, error) {
	orgent, err := org.FindOrgByLEICode(sess, lei, ro.plugin.source)

	if err != nil || orgent == nil {
		orgent, err = org.CreateOrgAsset(sess, ent, rel, o, ro.plugin.source)
	}

	return orgent, err
}

func (ro *relatedOrgs) process(e *et.Event, assets []*dbt.Entity) {
	for _, orgent := range assets {
		if o, valid := orgent.Asset.(*oamorg.Organization); valid {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
				Entity:  orgent,
				Session: e.Session,
			})
		}
	}
}
