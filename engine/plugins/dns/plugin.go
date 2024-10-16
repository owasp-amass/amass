// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/open-asset-model/source"
)

type dnsPlugin struct {
	name            string
	log             *slog.Logger
	apex            *dnsApex
	cname           *dnsCNAME
	ip              *dnsIP
	reverse         *dnsReverse
	subs            *dnsSubs
	firstSweepSize  int
	secondSweepSize int
	maxSweepSize    int
	source          *source.Source
}

func NewDNS() et.Plugin {
	return &dnsPlugin{
		name:            "DNS",
		firstSweepSize:  25,
		secondSweepSize: 100,
		maxSweepSize:    250,
		source: &source.Source{
			Name:       "DNS",
			Confidence: 100,
		},
	}
}

func (d *dnsPlugin) Name() string {
	return d.name
}

func (d *dnsPlugin) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	d.apex = &dnsApex{name: d.name + "-Apex", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.apex.name,
		Priority:     5,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.apex.check,
	}); err != nil {
		return err
	}

	d.cname = &dnsCNAME{name: d.name + "-CNAME", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.cname.name,
		Priority:     1,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.cname.check,
	}); err != nil {
		return err
	}

	d.ip = &dnsIP{
		name:    d.name + "-IP",
		queries: []uint16{dns.TypeA, dns.TypeAAAA},
		plugin:  d,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.ip.name,
		Priority:     2,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.FQDN,
		Callback:     d.ip.check,
	}); err != nil {
		return err
	}

	d.reverse = NewReverse(d)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.reverse.name,
		Priority:     9,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.IPAddress,
		Callback:     d.reverse.check,
	}); err != nil {
		return err
	}

	d.subs = NewSubs(d)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.subs.name,
		Priority:     4,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.subs.check,
	}); err != nil {
		return err
	}
	go d.subs.releaseSessions()

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsPlugin) Stop() {
	close(d.subs.done)
	d.log.Info("Plugin stopped")
}

func (d *dnsPlugin) lookupWithinTTL(session et.Session, name, atype string, since time.Time, rels ...string) []*dbt.Asset {
	var results []*dbt.Asset

	if len(rels) == 0 {
		return results
	}
	if !since.IsZero() {
		return results
	}

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if session.Done() {
			return
		}

		sincestr := since.Format("2006-01-02 15:04:05")
		from := "((((assets as fqdn inner join relations as records on fqdn.id = records.from_asset_id) "
		from2 := "inner join assets on records.to_asset_id = assets.id) "
		from3 := "inner join relations on relations.from_asset_id = assets.id) "
		from4 := "inner join assets as srcs on relations.to_asset_id = srcs.id) "
		where := "where fqdn.type = 'FQDN' and assets.type = '" + atype + "'"
		where2 := " and records.type in ('" + strings.Join(rels, "','") + "') "
		where3 := "and records.last_seen > '" + sincestr + "' "
		where4 := "and relations.type = 'source' and relations.last_seen > '" + sincestr + "' "
		where5 := " and srcs.type = 'Source' and srcs.content->>'name' = 'DNS'"
		like := " and fqdn.content->>'name' = '" + name + "'"

		query := from + from2 + from3 + from4 + where + where2 + where3 + where4 + where5 + like
		if assets, err := session.DB().AssetQuery(query); err == nil && len(assets) > 0 {
			results = append(results, assets...)
		}
	})
	<-done
	close(done)
	return results
}

func sweepCallback(e *et.Event, ip *oamnet.IPAddress, src *dbt.Asset) {
	if _, hit := e.Session.Cache().GetAsset(ip); hit {
		return
	}

	done := make(chan *dbt.Asset, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		addr, err := e.Session.DB().Create(nil, "", ip)
		if err == nil && addr != nil {
			_, _ = e.Session.DB().Link(addr, "source", src)
		}
		done <- addr
	})

	if addr := <-done; addr != nil {
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Asset:   addr,
			Session: e.Session,
		})
	}
}
