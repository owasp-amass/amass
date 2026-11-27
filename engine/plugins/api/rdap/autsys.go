// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// autsys is the RDAP query handler for an autonomous system: it turns the AS
// into the AutnumRecord its regional registry serves.
type autsys struct {
	name   string
	plugin *rdapPlugin
}

func (r *autsys) Name() string {
	return r.name
}

func (r *autsys) check(e *et.Event) error {
	as, ok := e.Entity.Asset.(*network.AutonomousSystem)
	if !ok {
		return errors.New("failed to cast the AutonomousSystem asset")
	}

	return r.plugin.checkRegistration(e, r.name, oam.AutnumRecord, dbt.ContentFilters{"number": as.Number},
		func() (*dbt.Entity, any) { return r.query(e, e.Entity) })
}

func (r *autsys) query(e *et.Event, asset *dbt.Entity) (*dbt.Entity, any) {
	_ = support.WaitLimit(e.Session.Ctx(), r.plugin.rlimit)

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Minute)
	defer cancel()

	as := asset.Asset.(*network.AutonomousSystem)
	resp, err := r.plugin.client.Do(rdap.NewAutnumRequest(uint32(as.Number)).WithContext(ctx))
	if err != nil {
		return nil, nil
	}

	record, ok := resp.Object.(*rdap.Autnum)
	if !ok || record == nil {
		return nil, nil
	}
	return r.store(e, record, asset), record
}

// store records the AutnumRecord of a response that carries its registration
// and last-changed dates.
func (r *autsys) store(e *et.Event, resp *rdap.Autnum, asset *dbt.Entity) *dbt.Entity {
	dates := eventDates(resp.Events)
	if dates.created == "" || dates.changed == "" {
		return nil
	}

	as := asset.Asset.(*network.AutonomousSystem)
	return r.plugin.storeRecord(e, asset, &oamreg.AutnumRecord{
		Number:      as.Number,
		Handle:      resp.Handle,
		Name:        resp.Name,
		WhoisServer: resp.Port43,
		Status:      resp.Status,
		CreatedDate: dates.created,
		UpdatedDate: dates.changed,
	})
}
