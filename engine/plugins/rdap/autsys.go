// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
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
	as, ok := e.Asset.Asset.(*network.AutonomousSystem)
	if !ok {
		return errors.New("failed to extract the AutonomousSystem asset")
	}

	src := support.GetSource(e.Session, r.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.AutonomousSystem), string(oam.AutnumRecord), r.name)
	if err != nil {
		return err
	}

	var asset *dbt.Asset
	var record *rdap.Autnum
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		asset = r.lookup(e, strconv.Itoa(as.Number), src, since)
	} else {
		asset, record = r.query(e, e.Asset, src)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if asset != nil {
		r.process(e, record, e.Asset, asset, src)
	}
	return nil
}

func (r *autsys) lookup(e *et.Event, num string, src *dbt.Asset, since time.Time) *dbt.Asset {
	if assets := support.SourceToAssetsWithinTTL(e.Session, num, string(oam.AutnumRecord), src, since); len(assets) > 0 {
		return assets[0]
	}
	return nil
}

func (r *autsys) query(e *et.Event, asset, src *dbt.Asset) (*dbt.Asset, *rdap.Autnum) {
	as := asset.Asset.(*network.AutonomousSystem)
	req := rdap.NewAutnumRequest(uint32(as.Number))

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	r.plugin.rlimit.Take()
	resp, err := r.plugin.client.Do(req)
	if err != nil {
		return nil, nil
	}

	record, ok := resp.Object.(*rdap.Autnum)
	if !ok {
		return nil, nil
	}
	return r.store(e, record, asset, src), record
}

func (r *autsys) store(e *et.Event, resp *rdap.Autnum, asset, src *dbt.Asset) *dbt.Asset {
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

	done := make(chan *dbt.Asset, 1)
	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		if a, err := e.Session.DB().Create(asset, "registration", autrec); err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", src)
			done <- a
			return
		}
		done <- nil
	})
	autasset := <-done
	close(done)
	return autasset
}

func (r *autsys) process(e *et.Event, record *rdap.Autnum, as, asset, src *dbt.Asset) {
	autnum := asset.Asset.(*oamreg.AutnumRecord)

	name := "AutnumRecord: " + autnum.Name
	_ = e.Dispatcher.DispatchEvent((&et.Event{
		Name:    name,
		Meta:    record,
		Asset:   asset,
		Session: e.Session,
	}))

	now := time.Now()
	if to, hit := e.Session.Cache().GetAsset(asset.Asset); hit && to != nil {
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "registration",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: as,
			ToAsset:   to,
		})
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: to,
			ToAsset:   src,
		})
		e.Session.Log().Info("relationship discovered", "from", autnum.Handle, "relation",
			"registration", "to", name, slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
	}
}
