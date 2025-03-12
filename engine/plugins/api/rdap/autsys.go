// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

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
		return errors.New("failed to extract the AutonomousSystem asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.AutonomousSystem), string(oam.AutnumRecord), r.name)
	if err != nil {
		return err
	}

	var asset *dbt.Entity
	var record *rdap.Autnum
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, r.plugin.source, since) {
		asset = r.lookup(e, strconv.Itoa(as.Number), since)
	} else {
		asset, record = r.query(e, e.Entity)
		support.MarkAssetMonitored(e.Session, e.Entity, r.plugin.source)
	}

	if asset != nil {
		r.process(e, record, asset)
	}
	return nil
}

func (r *autsys) lookup(e *et.Event, num string, since time.Time) *dbt.Entity {
	if assets := support.SourceToAssetsWithinTTL(e.Session, num, string(oam.AutnumRecord), r.plugin.source, since); len(assets) > 0 {
		return assets[0]
	}
	return nil
}

func (r *autsys) query(e *et.Event, asset *dbt.Entity) (*dbt.Entity, *rdap.Autnum) {
	as := asset.Asset.(*network.AutonomousSystem)
	req := rdap.NewAutnumRequest(uint32(as.Number))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	_ = r.plugin.rlimit.Wait(context.TODO())
	resp, err := r.plugin.client.Do(req)
	if err != nil {
		return nil, nil
	}

	record, ok := resp.Object.(*rdap.Autnum)
	if !ok {
		return nil, nil
	}
	return r.store(e, record, asset), record
}

func (r *autsys) store(e *et.Event, resp *rdap.Autnum, asset *dbt.Entity) *dbt.Entity {
	as := asset.Asset.(*network.AutonomousSystem)
	autrec := &oamreg.AutnumRecord{
		Number:      as.Number,
		Handle:      resp.Handle,
		Name:        resp.Name,
		WhoisServer: resp.Port43,
		Status:      resp.Status,
	}

	var reg, last bool
	for _, event := range resp.Events {
		if event.Action == "registration" {
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				autrec.CreatedDate = support.TimeToJSONString(&t)
				reg = true
			}
		} else if event.Action == "last changed" {
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				autrec.UpdatedDate = support.TimeToJSONString(&t)
				last = true
			}
		}
	}
	if !reg || !last {
		return nil
	}

	autasset, err := e.Session.Cache().CreateAsset(autrec)
	if err == nil && autasset != nil {
		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "registration"},
			FromEntity: asset,
			ToEntity:   autasset,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
				Source:     r.plugin.source.Name,
				Confidence: r.plugin.source.Confidence,
			})
		}
	}

	return autasset
}

func (r *autsys) process(e *et.Event, record *rdap.Autnum, asset *dbt.Entity) {
	autnum := asset.Asset.(*oamreg.AutnumRecord)

	name := "AutnumRecord: " + autnum.Name
	_ = e.Dispatcher.DispatchEvent((&et.Event{
		Name:    name,
		Meta:    record,
		Entity:  asset,
		Session: e.Session,
	}))

	e.Session.Log().Info("relationship discovered", "from", autnum.Handle, "relation",
		"registration", "to", name, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
}
