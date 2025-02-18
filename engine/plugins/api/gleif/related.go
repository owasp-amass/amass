// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

func (ro *relatedOrgs) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*general.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	} else if ident.Type != general.LEICode {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.Identifier), ro.name)
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

	if edges, err := e.Session.Cache().IncomingEdges(ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, ro.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					o = a
					break
				}
			}
		}
	}

	var p *dbt.Entity
	if edges, err := e.Session.Cache().IncomingEdges(o, since, "subsidiary"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, ro.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					p = a
					break
				}
			}
		}
	}

	var children []*dbt.Entity
	if edges, err := e.Session.Cache().OutgoingEdges(o, since, "subsidiary"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, ro.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					children = append(children, a)
				}
			}
		}
	}

	return append([]*dbt.Entity{o, p}, children...)
}

func (ro *relatedOrgs) query(e *et.Event, ident *dbt.Entity) []*dbt.Entity {
	id := ident.Asset.(*general.Identifier)

	parent, _ := ro.plugin.getDirectParent(id)
	children, _ := ro.plugin.getDirectChildren(id)
	return ro.store(e, ident, parent, children)
}

func (ro *relatedOrgs) store(e *et.Event, ident *dbt.Entity, parent *leiRecord, children []*leiRecord) []*dbt.Entity {
	var orgs []*dbt.Entity

	orgent := ro.plugin.leiToOrgEntity(e, ident)
	if orgent == nil {
		return orgs
	}

	if parent != nil {
		parentorg := &org.Organization{Name: parent.Attributes.Entity.LegalName.Name}

		parentent, err := support.CreateOrgAsset(e.Session, orgent, nil, parentorg, ro.plugin.source)
		if err == nil {
			orgs = append(orgs, parentent)
			ro.plugin.updateOrgFromLEIRecord(e, parentent, parent)
			support.MarkAssetMonitored(e.Session, parentent, ro.plugin.source)
			ro.plugin.createRelation(e.Session, parentent, &general.SimpleRelation{Name: "subsidiary"}, orgent)
		}
	}

	for _, child := range children {
		childorg := &org.Organization{Name: child.Attributes.Entity.LegalName.Name}

		childent, err := support.CreateOrgAsset(e.Session, orgent,
			&general.SimpleRelation{Name: "subsidiary"}, childorg, ro.plugin.source)
		if err == nil {
			orgs = append(orgs, childent)
			ro.plugin.updateOrgFromLEIRecord(e, childent, child)
			support.MarkAssetMonitored(e.Session, childent, ro.plugin.source)
		}
	}

	return orgs
}

func (ro *relatedOrgs) process(e *et.Event, assets []*dbt.Entity) {
	for _, orgent := range assets {
		o := orgent.Asset.(*org.Organization)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
			Entity:  orgent,
			Session: e.Session,
		})
	}
}
