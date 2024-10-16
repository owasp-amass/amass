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
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/resolve"
)

type dnsCNAME struct {
	name   string
	plugin *dnsPlugin
}

type relAlias struct {
	alias  *dbt.Asset
	target *dbt.Asset
}

func (d *dnsCNAME) check(e *et.Event) error {
	_, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	src := support.GetSource(e.Session, d.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	var alias []*relAlias
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		alias = append(alias, d.lookup(e, e.Asset, since)...)
	} else {
		alias = append(alias, d.query(e, e.Asset, src)...)
	}

	if len(alias) > 0 {
		d.process(e, alias, src)
	}
	return nil
}

func (d *dnsCNAME) lookup(e *et.Event, fqdn *dbt.Asset, since time.Time) []*relAlias {
	var alias []*relAlias

	n, ok := fqdn.Asset.(*domain.FQDN)
	if !ok || n == nil {
		return alias
	}

	if assets := d.plugin.lookupWithinTTL(e.Session, n.Name, "FQDN", since, "cname_record"); len(assets) > 0 {
		for _, a := range assets {
			alias = append(alias, &relAlias{alias: fqdn, target: a})
		}
	}
	return alias
}

func (d *dnsCNAME) query(e *et.Event, name, src *dbt.Asset) []*relAlias {
	var alias []*relAlias

	fqdn := name.Asset.(*domain.FQDN)
	if rr, err := support.PerformQuery(fqdn.Name, dns.TypeCNAME); err == nil {
		if records := d.store(e, name, src, rr); len(records) > 0 {
			alias = append(alias, records...)
			support.MarkAssetMonitored(e.Session, name, src)
		}
	}

	return alias
}

func (d *dnsCNAME) store(e *et.Event, fqdn, src *dbt.Asset, rr []*resolve.ExtractedAnswer) []*relAlias {
	var alias []*relAlias

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		for _, record := range rr {
			if record.Type != dns.TypeCNAME {
				continue
			}

			if cname, err := e.Session.DB().Create(fqdn, "cname_record", &domain.FQDN{Name: record.Data}); err == nil {
				if cname != nil {
					_, _ = e.Session.DB().Link(cname, "source", src)
					alias = append(alias, &relAlias{alias: fqdn, target: cname})
				}
			} else {
				e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		}
	})
	<-done
	close(done)
	return alias
}

func (d *dnsCNAME) process(e *et.Event, alias []*relAlias, src *dbt.Asset) {
	now := time.Now()

	for _, a := range alias {
		target := a.target.Asset.(*domain.FQDN)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    target.Name,
			Asset:   a.target,
			Session: e.Session,
		})

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: a.target,
			ToAsset:   src,
		})

		src := a.alias.Asset.(*domain.FQDN)
		if cname, hit := e.Session.Cache().GetAsset(a.alias.Asset); hit && cname != nil {
			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      "cname_record",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: cname,
				ToAsset:   a.target,
			})

			e.Session.Log().Info("relationship discovered", "from",
				src.Name, "relation", "cname_record", "to", target.Name,
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
}
