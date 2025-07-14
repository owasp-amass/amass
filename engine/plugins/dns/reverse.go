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
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve/utils"
)

type dnsReverse struct {
	name   string
	plugin *dnsPlugin
}

type relRev struct {
	ipFQDN *dbt.Entity
	target *dbt.Entity
}

func NewReverse(p *dnsPlugin) *dnsReverse {
	return &dnsReverse{
		name:   p.name + "-Reverse",
		plugin: p,
	}
}

func (d *dnsReverse) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	addrstr := ip.Address.String()
	if reserved, _ := amassnet.IsReservedAddress(addrstr); reserved {
		return nil
	}

	reverse, err := dns.ReverseAddr(ip.Address.String())
	if err != nil {
		return nil
	}
	reverse = utils.RemoveLastDot(reverse)

	src := d.plugin.source
	ptr := d.createPTRAlias(e, reverse, e.Entity)
	if ptr == nil {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), "IPAddress", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	var rev []*relRev
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		rev = append(rev, d.lookup(e, ptr, since)...)
	} else {
		rev = append(rev, d.query(e, addrstr, ptr)...)
		support.MarkAssetMonitored(e.Session, ptr, src)
	}

	if len(rev) > 0 {
		d.process(e, rev)
		support.AddDNSRecordType(e, int(dns.TypePTR))

		var size int
		if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf > 0 {
			size = d.plugin.secondSweepSize
			if e.Session.Config().Active {
				size = d.plugin.maxSweepSize
			}
		}
		if size > 0 {
			support.IPAddressSweep(e, ip, src, size, sweepCallback)
		}
	}
	return nil
}

func (d *dnsReverse) lookup(e *et.Event, fqdn *dbt.Entity, since time.Time) []*relRev {
	var rev []*relRev

	n, ok := fqdn.Asset.(*oamdns.FQDN)
	if !ok || n == nil {
		return rev
	}

	if assets := d.plugin.lookupWithinTTL(e.Session, n.Name, oam.FQDN, since, oam.BasicDNSRelation, 12); len(assets) > 0 {
		for _, a := range assets {
			rev = append(rev, &relRev{ipFQDN: fqdn, target: a})
		}
	}

	return rev
}

func (d *dnsReverse) query(e *et.Event, ipstr string, ptr *dbt.Entity) []*relRev {
	var rev []*relRev

	if rr, err := support.PerformQuery(ipstr, dns.TypePTR); err == nil {
		if records := d.store(e, ptr, rr); len(records) > 0 {
			rev = append(rev, records...)
		}
	}
	return rev
}

func (d *dnsReverse) store(e *et.Event, ptr *dbt.Entity, rr []dns.RR) []*relRev {
	var rev []*relRev
	// additional validation of the PTR record
	for _, record := range rr {
		if record.Header().Rrtype != dns.TypePTR {
			continue
		}

		data := strings.ToLower(strings.TrimSpace((record.(*dns.PTR)).Ptr))
		name := support.ScrapeSubdomainNames(data)
		if len(name) != 1 {
			continue
		}

		if t, err := e.Session.Cache().CreateAsset(&oamdns.FQDN{Name: name[0]}); err == nil && t != nil {
			if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
				Relation: &oamdns.BasicDNSRelation{
					Name: "dns_record",
					Header: oamdns.RRHeader{
						RRType: int(record.Header().Rrtype),
						Class:  int(record.Header().Class),
						TTL:    int(record.Header().Ttl),
					},
				},
				FromEntity: ptr,
				ToEntity:   t,
			}); err == nil && edge != nil {
				rev = append(rev, &relRev{ipFQDN: ptr, target: t})
				_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
					Source:     d.plugin.source.Name,
					Confidence: d.plugin.source.Confidence,
				})
			}
		} else {
			e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}

	return rev
}

func (d *dnsReverse) createPTRAlias(e *et.Event, name string, ip *dbt.Entity) *dbt.Entity {
	ptr, err := e.Session.Cache().CreateAsset(&oamdns.FQDN{Name: name})
	if err != nil || ptr == nil {
		return nil
	}
	if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
		Relation:   &general.SimpleRelation{Name: "ptr_record"},
		FromEntity: ip,
		ToEntity:   ptr,
	}); err == nil && edge != nil {
		_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
			Source:     d.plugin.source.Name,
			Confidence: d.plugin.source.Confidence,
		})
	}

	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    ptr.Asset.Key(),
		Entity:  ptr,
		Session: e.Session,
	})

	e.Session.Log().Info("relationship discovered", "from", ip.Asset.Key(), "relation", "ptr_record",
		"to", ptr.Asset.Key(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))

	return ptr
}

func (d *dnsReverse) process(e *et.Event, rev []*relRev) {
	for _, r := range rev {
		ip := r.ipFQDN.Asset.(*oamdns.FQDN)
		target := r.target.Asset.(*oamdns.FQDN)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    target.Name,
			Entity:  r.target,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", ip.Name, "relation", "ptr_record",
			"to", target.Name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
