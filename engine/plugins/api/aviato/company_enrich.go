// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package aviato

import (
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

func (ce *companyEnrich) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*general.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}

	ds := e.Session.Config().GetDataSourceConfig(ce.plugin.name)
	if ds == nil || len(ds.Creds) == 0 {
		return nil
	}

	var keys []string
	for _, cr := range ds.Creds {
		if cr != nil && cr.Apikey != "" {
			keys = append(keys, cr.Apikey)
		}
	}
	if len(keys) == 0 {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Identifier), string(oam.Organization), ce.plugin.name)
	if err != nil {
		return err
	}

	var o *dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, ce.plugin.source, since) {
		o = ce.lookup(e, e.Entity, since)
	} else {
		o = ce.query(e, e.Entity, keys)
		support.MarkAssetMonitored(e.Session, e.Entity, ce.plugin.source)
	}

	if o != nil {
		ce.process(e, e.Entity, o)
	}
	return nil
}

func (ce *companyEnrich) lookup(e *et.Event, ident *dbt.Entity, since time.Time) *dbt.Entity {
	if edges, err := e.Session.Cache().IncomingEdges(ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, ce.plugin.source.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.FromEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*org.Organization); ok {
					return a
				}
			}
		}
	}
	return nil
}

func (ce *companyEnrich) process(e *et.Event, ident, orgent *dbt.Entity) {
	o := orgent.Asset.(*org.Organization)

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    fmt.Sprintf("%s:%s", o.Name, o.ID),
		Entity:  orgent,
		Session: e.Session,
	})

	id := ident.Asset.(*general.Identifier)
	e.Session.Log().Info("relationship discovered", "from", id.UniqueID, "relation", "id",
		"to", o.Name, slog.Group("plugin", "name", ce.plugin.name, "handler", ce.name))
}
