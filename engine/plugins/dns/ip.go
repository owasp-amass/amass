// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"errors"
	"log/slog"
	"net/netip"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

type dnsIP struct {
	name    string
	queries []uint16
	plugin  *dnsPlugin
}

type relIP struct {
	rtype string
	ip    *dbt.Entity
}

func (d *dnsIP) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if _, found := support.IsCNAME(e.Session, fqdn); found {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "IPAddress", d.plugin.name)
	if err != nil {
		return err
	}

	var ips []*relIP
	src := d.plugin.source
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, src, since) {
		ips = append(ips, d.lookup(e, fqdn.Name, since)...)
	} else {
		ips = append(ips, d.query(e, e.Entity, src)...)
	}

	if len(ips) > 0 {
		d.process(e, fqdn.Name, ips)

		for _, v := range ips {
			ip, ok := v.ip.Asset.(*oamnet.IPAddress)
			if !ok || ip == nil {
				continue
			}

			var size int
			if _, conf := e.Session.Scope().IsAssetInScope(ip, 0); conf > 0 {
				size = d.plugin.secondSweepSize
				if e.Session.Config().Active {
					size = d.plugin.maxSweepSize
				}
			} else if _, conf2 := e.Session.Scope().IsAssetInScope(fqdn, 0); conf2 > 0 {
				size = d.plugin.firstSweepSize
			}
			if size > 0 {
				support.IPAddressSweep(e, ip, src, size, sweepCallback)
			}
		}
	}
	return nil
}

func (d *dnsIP) lookup(e *et.Event, fqdn string, since time.Time) []*relIP {
	var ips []*relIP

	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, oam.IPAddress, since, oam.BasicDNSRelation, 1); len(assets) > 0 {
		for _, a := range assets {
			ips = append(ips, &relIP{rtype: "dns_record", ip: a})
		}
	}
	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, oam.IPAddress, since, oam.BasicDNSRelation, 28); len(assets) > 0 {
		for _, a := range assets {
			ips = append(ips, &relIP{rtype: "dns_record", ip: a})
		}
	}

	return ips
}

func (d *dnsIP) query(e *et.Event, name *dbt.Entity, src *et.Source) []*relIP {
	var ips []*relIP

	fqdn := name.Asset.(*oamdns.FQDN)
	for _, qtype := range d.queries {
		if rr, err := support.PerformQuery(fqdn.Name, qtype); err == nil {
			if records := d.store(e, name, src, rr); len(records) > 0 {
				ips = append(ips, records...)
				support.MarkAssetMonitored(e.Session, name, src)
			}
		}
	}

	return ips
}

func (d *dnsIP) store(e *et.Event, fqdn *dbt.Entity, src *et.Source, rr []*resolve.ExtractedAnswer) []*relIP {
	var ips []*relIP

	for _, record := range rr {
		if record.Type == dns.TypeA {
			if ip, err := e.Session.Cache().CreateAsset(&oamnet.IPAddress{Address: netip.MustParseAddr(record.Data), Type: "IPv4"}); err == nil && ip != nil {
				if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
					Relation: &oamdns.BasicDNSRelation{
						Name: "dns_record",
						Header: oamdns.RRHeader{
							RRType: int(record.Type),
							Class:  1,
						},
					},
					FromEntity: fqdn,
					ToEntity:   ip,
				}); err == nil && edge != nil {
					ips = append(ips, &relIP{rtype: "dns_record", ip: ip})
					_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
						Source:     src.Name,
						Confidence: src.Confidence,
					})
				}
			} else {
				e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		} else if record.Type == dns.TypeAAAA {
			if ip, err := e.Session.Cache().CreateAsset(&oamnet.IPAddress{Address: netip.MustParseAddr(record.Data), Type: "IPv6"}); err == nil {
				if edge, err := e.Session.Cache().CreateEdge(&dbt.Edge{
					Relation: &oamdns.BasicDNSRelation{
						Name: "dns_record",
						Header: oamdns.RRHeader{
							RRType: int(record.Type),
							Class:  1,
						},
					},
					FromEntity: fqdn,
					ToEntity:   ip,
				}); err == nil && edge != nil {
					ips = append(ips, &relIP{rtype: "dns_record", ip: ip})
					_, _ = e.Session.Cache().CreateEdgeProperty(edge, &general.SourceProperty{
						Source:     src.Name,
						Confidence: src.Confidence,
					})
				}
			} else {
				e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		}
	}

	return ips
}

func (d *dnsIP) process(e *et.Event, name string, addrs []*relIP) {
	for _, a := range addrs {
		ip := a.ip.Asset.(*oamnet.IPAddress)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Entity:  a.ip,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", name, "relation", a.rtype,
			"to", ip.Address.String(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
