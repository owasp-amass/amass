// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
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
	n, ok := e.Asset.Asset.(*network.Netblock)
	if !ok {
		return errors.New("failed to extract the Netblock asset")
	}

	src := support.GetSource(e.Session, nb.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.Netblock), string(oam.IPNetRecord), nb.name)
	if err != nil {
		return err
	}

	var asset *dbt.Asset
	var record *rdap.IPNetwork
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		asset = nb.lookup(e, n.CIDR.String(), src, since)
	} else {
		asset, record = nb.query(e, e.Asset, src)
		support.MarkAssetMonitored(e.Session, e.Asset, src)
	}

	if asset != nil {
		nb.process(e, record, e.Asset, asset, src)
	}
	return nil
}

func (nb *netblock) lookup(e *et.Event, cidr string, src *dbt.Asset, since time.Time) *dbt.Asset {
	if assets := support.SourceToAssetsWithinTTL(e.Session, cidr, string(oam.IPNetRecord), src, since); len(assets) > 0 {
		return assets[0]
	}
	return nil
}

func (nb *netblock) query(e *et.Event, asset, src *dbt.Asset) (*dbt.Asset, *rdap.IPNetwork) {
	n := asset.Asset.(*network.Netblock)

	var req *rdap.Request
	_, ipnet, err := net.ParseCIDR(n.CIDR.String())
	if err != nil {
		return nil, nil
	}
	req = rdap.NewIPNetRequest(ipnet)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req = req.WithContext(ctx)

	nb.plugin.rlimit.Take()
	resp, err := nb.plugin.client.Do(req)
	if err != nil {
		return nil, nil
	}

	record, ok := resp.Object.(*rdap.IPNetwork)
	if !ok {
		return nil, nil
	}
	return nb.store(e, record, asset, src), record
}

func (nb *netblock) store(e *et.Event, resp *rdap.IPNetwork, asset, src *dbt.Asset) *dbt.Asset {
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
		if event.Action == "registration" {
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				ipnetrec.CreatedDate = support.TimeToJSONString(&t)
				reg = true
			}
		} else if event.Action == "last changed" {
			if t, err := time.Parse(time.RFC3339, event.Date); err == nil {
				ipnetrec.UpdatedDate = support.TimeToJSONString(&t)
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

		if a, err := e.Session.DB().Create(asset, "registration", ipnetrec); err == nil && a != nil {
			_, _ = e.Session.DB().Link(a, "source", src)
			done <- a
			return
		}
		done <- nil
	})
	a := <-done
	close(done)
	return a
}

func (nb *netblock) process(e *et.Event, record *rdap.IPNetwork, n, asset, src *dbt.Asset) {
	ipnet := asset.Asset.(*oamreg.IPNetRecord)

	name := "IPNetRecord: " + ipnet.Handle
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
			FromAsset: n,
			ToAsset:   to,
		})
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: to,
			ToAsset:   src,
		})
		e.Session.Log().Info("relationship discovered", "from", ipnet.CIDR.String(), "relation",
			"registration", "to", name, slog.Group("plugin", "name", nb.plugin.name, "handler", nb.name))
	}
}
