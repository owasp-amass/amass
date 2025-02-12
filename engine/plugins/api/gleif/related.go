// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

type relatedOrgs struct {
	name   string
	plugin *gleif
}

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
		orgs = append(orgs, ro.lookup(e, e.Entity, ro.plugin.source, since)...)
	} else {
		orgs = append(orgs, ro.query(e, ident, ro.plugin.source)...)
		support.MarkAssetMonitored(e.Session, e.Entity, ro.plugin.source)
	}

	if len(orgs) > 0 {
		ro.process(e, orgs, ro.plugin.source)
	}
	return nil
}

func (ro *relatedOrgs) lookup(e *et.Event, ident *dbt.Entity, src *et.Source, since time.Time) []*dbt.Entity {
	var o *dbt.Entity

	if edges, err := e.Session.Cache().IncomingEdges(ident, since, "id"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, src.Name); err != nil || len(tags) == 0 {
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
	if edges, err := e.Session.Cache().OutgoingEdges(o, since, "parent"); err == nil {
		for _, edge := range edges {
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, src.Name); err != nil || len(tags) == 0 {
				continue
			}
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
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
			if tags, err := e.Session.Cache().GetEdgeTags(edge, since, src.Name); err != nil || len(tags) == 0 {
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

func (ro *relatedOrgs) query(e *et.Event, ident *general.Identifier, src *et.Source) []*dbt.Entity {
	u := "https://api.gleif.org/api/v1/lei-records/" + ident.EntityID

	ro.plugin.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		return nil
	}

	var result singleResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil {
		return nil
	}

	return ro.store(e, &result, src)
}

func (ro *relatedOrgs) store(e *et.Event, lei *singleResponse, src *et.Source) []*dbt.Entity {
	return nil
}

func (ro *relatedOrgs) process(e *et.Event, assets []*dbt.Entity, src *et.Source) {
	return
}
