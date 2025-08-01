// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func (fc *fuzzyCompletions) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamorg.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Organization), string(oam.Identifier), fc.plugin.name)
	if err != nil {
		return err
	}

	var id *dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, fc.plugin.source, since) {
		id = fc.lookup(e, e.Entity, since)
	} else {
		id = fc.query(e, e.Entity)
		support.MarkAssetMonitored(e.Session, e.Entity, fc.plugin.source)
	}

	if id != nil {
		fc.process(e, e.Entity, id)
	}
	return nil
}

func (fc *fuzzyCompletions) lookup(e *et.Event, orgent *dbt.Entity, since time.Time) *dbt.Entity {
	if edges, err := e.Session.Cache().OutgoingEdges(orgent, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge,
				since, fc.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if id, ok := a.Asset.(*general.Identifier); ok && id != nil && id.Type == general.LEICode {
					return a
				}
			}
		}
	}
	return nil
}

func (fc *fuzzyCompletions) query(e *et.Event, orgent *dbt.Entity) *dbt.Entity {
	var conf int
	var rec *org.LEIRecord

	if leient := fc.plugin.orgEntityToLEI(e, orgent); leient != nil {
		lei := leient.Asset.(*general.Identifier)

		if r, err := org.GLEIFGetLEIRecord(lei.ID); err == nil {
			rec = r
			conf = 100
		}
	}

	if rec == nil {
		o := orgent.Asset.(*oamorg.Organization)
		brand := org.ExtractBrandName(o.Name)
		_ = fc.plugin.rlimit.Wait(context.TODO())

		var err error
		rec, err = org.GLEIFSearchFuzzyCompletions(e, orgent, brand)
		if err != nil {
			e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
			return nil
		}
	}

	if rec == nil {
		e.Session.Log().Info("no LEI record found for organization",
			"org", orgent.ID, slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
		return nil
	}
	return fc.store(e, orgent, rec, conf)
}

func (fc *fuzzyCompletions) store(e *et.Event, orgent *dbt.Entity, rec *org.LEIRecord, conf int) *dbt.Entity {
	fc.plugin.updateOrgFromLEIRecord(e, orgent, rec, conf)

	ident, err := fc.plugin.createLEIFromRecord(e, orgent, rec, conf)
	if err != nil {
		e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
		return nil
	}

	return ident
}

func (fc *fuzzyCompletions) process(e *et.Event, orgent, ident *dbt.Entity) {
	id := ident.Asset.(*general.Identifier)

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    id.UniqueID,
		Entity:  ident,
		Session: e.Session,
	})

	o := orgent.Asset.(*oamorg.Organization)
	e.Session.Log().Info("relationship discovered", "from", o.Name, "relation", "id",
		"to", id.UniqueID, slog.Group("plugin", "name", fc.plugin.name, "handler", fc.name))
}
