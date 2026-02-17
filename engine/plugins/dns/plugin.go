// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"log/slog"
	"sync"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type dnsPlugin struct {
	name            string
	txt             *dnsTXT
	log             *slog.Logger
	apex            *dnsApex
	cname           *dnsCNAME
	ip              *dnsIP
	reverse         *dnsReverse
	subs            *dnsSubs
	firstSweepSize  int
	secondSweepSize int
	maxSweepSize    int
	source          *et.Source
	apexLock        sync.RWMutex
	apexList        map[string]*dbt.Entity
}

func NewDNS() et.Plugin {
	return &dnsPlugin{
		name:            "DNS",
		firstSweepSize:  25,
		secondSweepSize: 100,
		maxSweepSize:    250,
		source: &et.Source{
			Name:       "DNS",
			Confidence: 100,
		},
		apexList: make(map[string]*dbt.Entity),
	}
}

func (d *dnsPlugin) Name() string {
	return d.name
}

func (d *dnsPlugin) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	cname := d.name + "-CNAME"
	d.cname = &dnsCNAME{
		name:   cname,
		plugin: d,
		source: &et.Source{
			Name:       cname,
			Confidence: 100,
		},
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.cname.name,
		Position:     2,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.cname.check,
	}); err != nil {
		return err
	}

	ipname := d.name + "-IP"
	d.ip = &dnsIP{
		name:    ipname,
		queries: []uint16{dns.TypeA, dns.TypeAAAA},
		plugin:  d,
		source: &et.Source{
			Name:       ipname,
			Confidence: 100,
		},
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.ip.name,
		Position:     3,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.IPAddress)},
		EventType:    oam.FQDN,
		Callback:     d.ip.check,
	}); err != nil {
		return err
	}

	d.subs = NewSubs(d)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.subs.name,
		Position:     7,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.subs.check,
	}); err != nil {
		return err
	}
	go d.subs.releaseSessions()

	d.apex = &dnsApex{name: d.name + "-Apex", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.apex.name,
		Position:     8,
		Exclusive:    true,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.apex.check,
	}); err != nil {
		return err
	}

	txtname := d.name + "-TXT"
	d.txt = &dnsTXT{
		name:   d.name + "-TXT",
		plugin: d,
		source: &et.Source{
			Name:       txtname,
			Confidence: 100,
		},
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.txt.name,
		Position:     9,
		Exclusive:    true,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.txt.check,
	}); err != nil {
		return err
	}

	d.reverse = NewReverse(d)
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.reverse.name,
		Position:     8,
		Exclusive:    true,
		MaxInstances: support.MinHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.IPAddress,
		Callback:     d.reverse.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *dnsPlugin) Stop() {
	close(d.subs.done)
	d.log.Info("Plugin stopped")
}

func (d *dnsPlugin) lookupWithinTTL(session et.Session, fent *dbt.Entity, atype oam.AssetType, since time.Time, reltype oam.RelationType, rrtypes ...int) []*dbt.Entity {
	var results []*dbt.Entity

	if len(rrtypes) == 0 || since.IsZero() {
		return results
	}

	ctx, cancel := context.WithTimeout(session.Ctx(), 30*time.Second)
	defer cancel()

	if edges, err := session.DB().OutgoingEdges(ctx, fent, since, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			var rrtype int

			switch v := edge.Relation.(type) {
			case *oamdns.BasicDNSRelation:
				if v.RelationType() == reltype {
					rrtype = v.Header.RRType
				}
			case *oamdns.PrefDNSRelation:
				if v.RelationType() == reltype {
					rrtype = v.Header.RRType
				}
			case *oamdns.SRVDNSRelation:
				if v.RelationType() == reltype {
					rrtype = v.Header.RRType
				}
			}

			var found bool
			for _, t := range rrtypes {
				if t == rrtype {
					found = true
					break
				}
			}
			if !found {
				continue
			}

			if tags, err := session.DB().FindEdgeTags(ctx, edge, since, d.source.Name); err == nil && len(tags) > 0 {
				var found bool

				for _, tag := range tags {
					if _, ok := tag.Property.(*general.SourceProperty); ok {
						found = true
						break
					}
				}
				if !found {
					continue
				}
			}

			if to, err := session.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil && to != nil && to.Asset.AssetType() == atype {
				results = append(results, to)
			}
		}
	}

	return results
}

func sweepCallback(e *et.Event, ip *oamnet.IPAddress, src *et.Source) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	// ensure we do not work on an IP address that was processed previously
	_, err := e.Session.DB().FindEntitiesByContent(ctx, oam.IPAddress, e.Session.StartTime(), 1, dbt.ContentFilters{
		"address": ip.Address.String(),
	})
	if err == nil {
		return
	}

	entity, err := e.Session.DB().CreateAsset(ctx, ip)
	if err == nil && entity != nil {
		_, _ = e.Session.DB().CreateEntityProperty(ctx, entity, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Entity:  entity,
			Session: e.Session,
		})
	}
}

func (d *dnsPlugin) addApex(name string, entity *dbt.Entity) {
	d.apexLock.Lock()
	defer d.apexLock.Unlock()

	if _, found := d.apexList[name]; !found {
		d.apexList[name] = entity
	}
}

func (d *dnsPlugin) getApex(name string) *dbt.Entity {
	d.apexLock.RLock()
	defer d.apexLock.RUnlock()

	if entity, found := d.apexList[name]; found {
		return entity
	}
	return nil
}

func (d *dnsPlugin) getApexList() []string {
	d.apexLock.RLock()
	defer d.apexLock.RUnlock()

	var results []string
	for name := range d.apexList {
		results = append(results, name)
	}
	return results
}
