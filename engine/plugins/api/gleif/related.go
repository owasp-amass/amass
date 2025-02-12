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
)

type relatedOrgs struct {
	name   string
	plugin *gleif
}

func (ro *relatedOrgs) check(e *et.Event) error {
	ident, ok := e.Entity.Asset.(*general.Identifier)
	if !ok {
		return errors.New("failed to extract the Identifier asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Identifier), string(oam.Identifier), lr.name)
	if err != nil {
		return err
	}

	var names []*dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, ro.plugin.source, since) {
		names = append(names, ro.lookup(e, ident, ro.plugin.source, since)...)
	} else {
		names = append(names, ro.query(e, ident, ro.plugin.source)...)
		support.MarkAssetMonitored(e.Session, e.Entity, ro.plugin.source)
	}

	if len(names) > 0 {
		ro.process(e, names, ro.plugin.source)
	}
	return nil
}

func (ro *relatedOrgs) lookup(e *et.Event, ident *general.Identifier, src *et.Source, since time.Time) []*dbt.Entity {
	return support.SourceToAssetsWithinTTL(e.Session, ident.Key(), string(oam.Identifier), ro.plugin.source, since)
}

func (ro *relatedOrgs) query(e *et.Event, ident *general.Identifier, src *et.Source) []*dbt.Entity {
	u := "https://api.gleif.org/api/v1/lei-records/" + ident.EntityID

	ro.plugin.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		return nil
	}

	var result singleResponse
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil || len(result.Data) == 0 {
		return nil
	}

	return ro.store(e, &result, ro.plugin.source)
}

func (ro *relatedOrgs) store(e *et.Event, lei *singleResponse, src *et.Source) []*dbt.Entity {
	return nil
}

func (ro *relatedOrgs) process(e *et.Event, assets []*dbt.Entity, src *et.Source) {
	return
}
