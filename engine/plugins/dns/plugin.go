// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"log/slog"
	"time"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

type dnsPlugin struct {
	name            string
	log             *slog.Logger
	apex            *dnsApex
	cname           *dnsCNAME
	ip              *dnsIP
	txt             *dnsTXT
	reverse         *dnsReverse
	subs            *dnsSubs
	firstSweepSize  int
	secondSweepSize int
	maxSweepSize    int
	source          *et.Source
	apexList        *stringset.Set
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
		apexList: stringset.New(),
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
		Priority:     8,
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

	d.txt = &dnsTXT{name: d.name + "-TXT", plugin: d}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.txt.name,
		Priority:     3,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.FQDN)},
		EventType:    oam.FQDN,
		Callback:     d.txt.check,
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

func (d *dnsPlugin) lookupWithinTTL(session et.Session, name string, atype oam.AssetType, since time.Time, reltype oam.RelationType, rrtypes ...int) []*dbt.Entity {
	var results []*dbt.Entity

	if len(rrtypes) == 0 || !since.IsZero() {
		return results
	}

	ents, err := session.Cache().FindEntitiesByContent(&oamdns.FQDN{Name: name}, time.Time{})
	if err != nil || len(ents) != 1 {
		return results
	}
	entity := ents[0]

	if edges, err := session.Cache().OutgoingEdges(entity, since, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if tags, err := session.Cache().GetEdgeTags(edge, since, d.source.Name); err == nil && len(tags) > 0 {
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

			for _, t := range rrtypes {
				if rrtype == t {
					if to, err := session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && to != nil && to.Asset.AssetType() == atype {
						results = append(results, to)
						break
					}
				}
			}
		}
	}

	return results
}

func sweepCallback(e *et.Event, ip *oamnet.IPAddress, src *et.Source) {
	entity, err := e.Session.Cache().CreateAsset(ip)
	if err == nil && entity != nil {
		_, _ = e.Session.Cache().CreateEntityProperty(entity, &general.SourceProperty{
			Source:     src.Name,
			Confidence: src.Confidence,
		})
	}

	if entity != nil {
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Entity:  entity,
			Session: e.Session,
		})
	}
}
