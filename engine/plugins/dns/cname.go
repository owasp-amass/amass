// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"log/slog"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/property"
	"github.com/owasp-amass/open-asset-model/relation"
	"github.com/owasp-amass/resolve"
)

type dnsCNAME struct {
	name   string
	plugin *dnsPlugin
}

type relAlias struct {
	alias  *dbt.Entity
	target *dbt.Entity
}

func (d *dnsCNAME) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	var alias []*relAlias
	src := d.plugin.source
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		alias = append(alias, d.lookup(e, e.Entity, since)...)
	} else {
		alias = append(alias, d.query(e, e.Entity)...)
	}

	if len(alias) > 0 {
		d.process(e, alias)
	}
	return nil
}

func (d *dnsCNAME) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*relAlias {
	var alias []*relAlias

	n, ok := fqdn.Asset.(*domain.FQDN)
	if !ok || n == nil {
		return alias
	}

	if assets := d.plugin.lookupWithinTTL(e.Session, n.Name, oam.FQDN, since, oam.BasicDNSRelation, 5); len(assets) > 0 {
		for _, a := range assets {
			alias = append(alias, &relAlias{alias: fqdn, target: a})
		}
	}
	return alias
}

func (d *dnsCNAME) query(e *et.Event, name *dbt.Entity) []*relAlias {
	var alias []*relAlias

	fqdn := name.Asset.(*domain.FQDN)
	if rr, err := support.PerformQuery(fqdn.Name, dns.TypeCNAME); err == nil {
		if records := d.store(e, name, rr); len(records) > 0 {
			alias = append(alias, records...)
			support.MarkAssetMonitored(e.Session, name, d.plugin.source)
		}
	}

	return alias
}

func (d *dnsCNAME) store(e *et.Event, fqdn *dbt.Entity, rr []*resolve.ExtractedAnswer) []*relAlias {
	var alias []*relAlias

	for _, record := range rr {
		if record.Type != dns.TypeCNAME {
			continue
		}

		if cname, err := e.Session.Cache().CreateAsset(&domain.FQDN{Name: record.Data}); err == nil && cname != nil {
			if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
				Relation: &relation.BasicDNSRelation{
					Name: "dns_record",
					Header: relation.RRHeader{
						RRType: int(record.Type),
						Class:  1,
					},
				},
				FromEntity: fqdn,
				ToEntity:   cname,
			}); err == nil && edge != nil {
				alias = append(alias, &relAlias{alias: fqdn, target: cname})
				_, _ = e.Session.Cache().CreateEdgeProperty(edge, &property.SourceProperty{
					Source:     d.plugin.source.Name,
					Confidence: d.plugin.source.Confidence,
				})
			} else {
				e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		} else {
			e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}

	return alias
}

func (d *dnsCNAME) process(e *et.Event, alias []*relAlias) {
	for _, a := range alias {
		target := a.target.Asset.(*domain.FQDN)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    target.Name,
			Entity:  a.target,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", d.plugin.source.Name, "relation",
			"cname_record", "to", target.Name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
