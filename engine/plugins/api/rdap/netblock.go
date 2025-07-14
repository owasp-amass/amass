// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package rdap

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/openrdap/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/network"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

type netblock struct {
	name   string
	plugin *rdapPlugin
}

func (nb *netblock) Name() string {
	return nb.name
}

func (nb *netblock) check(e *et.Event) error {
	n, ok := e.Entity.Asset.(*network.Netblock)
	if !ok {
		return errors.New("failed to extract the Netblock asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Netblock), string(oam.IPNetRecord), nb.name)
	if err != nil {
		return err
	}

	var asset *dbt.Entity
	var record *rdap.IPNetwork
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, nb.plugin.source, since) {
		asset = nb.lookup(e, n.CIDR.String(), since)
	} else {
		asset, record = nb.query(e, e.Entity)
		support.MarkAssetMonitored(e.Session, e.Entity, nb.plugin.source)
	}

	if asset != nil {
		nb.process(e, record, asset)
	}
	return nil
}

func (nb *netblock) lookup(e *et.Event, cidr string, since time.Time) *dbt.Entity {
	if assets := support.SourceToAssetsWithinTTL(e.Session, cidr, string(oam.IPNetRecord), nb.plugin.source, since); len(assets) > 0 {
		return assets[0]
	}
	return nil
}

func (nb *netblock) query(e *et.Event, asset *dbt.Entity) (*dbt.Entity, *rdap.IPNetwork) {
	n := asset.Asset.(*network.Netblock)

	_, ipnet, err := net.ParseCIDR(n.CIDR.String())
	if err != nil {
		return nil, nil
	}
	req := rdap.NewIPNetRequest(ipnet)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	_ = nb.plugin.rlimit.Wait(context.TODO())
	resp, err := nb.plugin.client.Do(req)
	if err != nil {
		return nil, nil
	}

	record, ok := resp.Object.(*rdap.IPNetwork)
	if !ok {
		return nil, nil
	}
	return nb.store(e, record, asset), record
}

func (nb *netblock) store(e *et.Event, resp *rdap.IPNetwork, asset *dbt.Entity) *dbt.Entity {
	n := asset.Asset.(*network.Netblock)
	ipnetrec := &oamreg.IPNetRecord{
		CIDR:         n.CIDR,
		Handle:       resp.Handle,
		StartAddress: netip.MustParseAddr(resp.StartAddress),
		EndAddress:   netip.MustParseAddr(resp.EndAddress),
		Type:         n.Type,
		Name:         resp.Name,
		Method:       resp.Type,
		Country:      resp.Country,
		ParentHandle: resp.ParentHandle,
		WhoisServer:  resp.Port43,
		Status:       resp.Status,
	}

	var reg, last bool
	for _, event := range resp.Events {
		switch event.Action {
		case "registration":
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				ipnetrec.CreatedDate = support.TimeToJSONString(&t)
				reg = true
			}
		case "last changed":
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				ipnetrec.UpdatedDate = support.TimeToJSONString(&t)
				last = true
			}
		}
	}
	if !reg || !last {
		return nil
	}

	record, err := e.Session.Cache().CreateAsset(ipnetrec)
	if err == nil && record != nil {
		_, _ = e.Session.Cache().CreateEntityProperty(record, &general.SourceProperty{
			Source:     nb.plugin.source.Name,
			Confidence: nb.plugin.source.Confidence,
		})

		if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
			Relation:   &general.SimpleRelation{Name: "registration"},
			FromEntity: asset,
			ToEntity:   record,
		}); err == nil && edge != nil {
			_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
				Source:     nb.plugin.source.Name,
				Confidence: nb.plugin.source.Confidence,
			})
		}
	}
	return record
}

func (nb *netblock) process(e *et.Event, record *rdap.IPNetwork, asset *dbt.Entity) {
	ipnet := asset.Asset.(*oamreg.IPNetRecord)

	name := "IPNetRecord: " + ipnet.Handle
	_ = e.Dispatcher.DispatchEvent((&et.Event{
		Name:    name,
		Meta:    record,
		Entity:  asset,
		Session: e.Session,
	}))

	e.Session.Log().Info("relationship discovered", "from", ipnet.CIDR.String(), "relation",
		"registration", "to", name, slog.Group("plugin", "name", nb.plugin.name, "handler", nb.name))
}
