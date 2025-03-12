// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/resolve"
)

type dnsCNAME struct {
	name   string
	plugin *dnsPlugin
	source *et.Source
}

type relAlias struct {
	alias  *dbt.Entity
	target *dbt.Entity
}

func (d *dnsCNAME) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	var alias []*relAlias
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		alias = append(alias, d.lookup(e, e.Entity, since)...)
	} else {
		alias = append(alias, d.query(e, e.Entity)...)
	}

	if len(alias) > 0 {
		d.process(e, alias)
		support.AddDNSRecordType(e, int(dns.TypeCNAME))
	}
	return nil
}

func (d *dnsCNAME) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*relAlias {
	var alias []*relAlias

	n, ok := fqdn.Asset.(*oamdns.FQDN)
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

	fqdn := name.Asset.(*oamdns.FQDN)
	if rr, err := support.PerformQuery(fqdn.Name, dns.TypeCNAME); err == nil {
		if records := d.store(e, name, rr); len(records) > 0 {
			alias = append(alias, records...)
			support.MarkAssetMonitored(e.Session, name, d.source)
		}
	}

	return alias
}

func (d *dnsCNAME) store(e *et.Event, fqdn *dbt.Entity, rr []dns.RR) []*relAlias {
	var alias []*relAlias

	for _, record := range rr {
		if record.Header().Rrtype != dns.TypeCNAME {
			continue
		}

		data := strings.ToLower(strings.TrimSpace((record.(*dns.CNAME)).Target))
		name := resolve.RemoveLastDot(data)
		if cname, err := e.Session.Cache().CreateAsset(&oamdns.FQDN{Name: name}); err == nil && cname != nil {
			if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
				Relation: &oamdns.BasicDNSRelation{
					Name: "dns_record",
					Header: oamdns.RRHeader{
						RRType: int(record.Header().Rrtype),
						Class:  int(record.Header().Class),
						TTL:    int(record.Header().Ttl),
					},
				},
				FromEntity: fqdn,
				ToEntity:   cname,
			}); err == nil && edge != nil {
				alias = append(alias, &relAlias{alias: fqdn, target: cname})
				_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
					Source:     d.source.Name,
					Confidence: d.source.Confidence,
				})
			}
		}
	}

	return alias
}

func (d *dnsCNAME) process(e *et.Event, alias []*relAlias) {
	for _, a := range alias {
		target := a.target.Asset.(*oamdns.FQDN)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    target.Name,
			Entity:  a.target,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", d.plugin.source.Name, "relation",
			"cname_record", "to", target.Name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
