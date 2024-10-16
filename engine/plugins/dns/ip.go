// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
	"github.com/owasp-amass/open-asset-model/domain"
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
	ip    *dbt.Asset
}

func (d *dnsIP) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if _, found := support.IsCNAME(e.Session, fqdn); found {
		return nil
	}

	src := support.GetSource(e.Session, d.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "IPAddress", d.plugin.name)
	if err != nil {
		return err
	}

	var ips []*relIP
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		ips = append(ips, d.lookup(e, fqdn.Name, since)...)
	} else {
		ips = append(ips, d.query(e, e.Asset, src)...)
	}

	if len(ips) > 0 {
		d.process(e, fqdn.Name, ips, src)

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

	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, "IPAddress", since, "a_record"); len(assets) > 0 {
		for _, a := range assets {
			ips = append(ips, &relIP{rtype: "a_record", ip: a})
		}
	}
	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, "IPAddress", since, "aaaa_record"); len(assets) > 0 {
		for _, a := range assets {
			ips = append(ips, &relIP{rtype: "aaaa_record", ip: a})
		}
	}

	return ips
}

func (d *dnsIP) query(e *et.Event, name, src *dbt.Asset) []*relIP {
	var ips []*relIP

	fqdn := name.Asset.(*domain.FQDN)
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

func (d *dnsIP) store(e *et.Event, fqdn, src *dbt.Asset, rr []*resolve.ExtractedAnswer) []*relIP {
	var ips []*relIP

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		for _, record := range rr {
			if record.Type == dns.TypeA {
				if ip, err := e.Session.DB().Create(fqdn, "a_record", &oamnet.IPAddress{Address: netip.MustParseAddr(record.Data), Type: "IPv4"}); err == nil {
					if ip != nil {
						_, _ = e.Session.DB().Link(ip, "source", src)
						ips = append(ips, &relIP{rtype: "a_record", ip: ip})
					}
				} else {
					e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
				}
			} else if record.Type == dns.TypeAAAA {
				if ip, err := e.Session.DB().Create(fqdn, "aaaa_record", &oamnet.IPAddress{Address: netip.MustParseAddr(record.Data), Type: "IPv6"}); err == nil {
					if ip != nil {
						_, _ = e.Session.DB().Link(ip, "source", src)
						ips = append(ips, &relIP{rtype: "aaaa_record", ip: ip})
					}
				} else {
					e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
				}
			}
		}
	})
	<-done
	close(done)
	return ips
}

func (d *dnsIP) process(e *et.Event, name string, addrs []*relIP, src *dbt.Asset) {
	now := time.Now()

	for _, a := range addrs {
		ip := a.ip.Asset.(*oamnet.IPAddress)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    ip.Address.String(),
			Asset:   a.ip,
			Session: e.Session,
		})

		addr, hit := e.Session.Cache().GetAsset(a.ip.Asset)
		if !hit || addr == nil {
			continue
		}

		fqdn, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: name})
		if !hit || fqdn == nil {
			continue
		}

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      a.rtype,
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: fqdn,
			ToAsset:   addr,
		})
		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: addr,
			ToAsset:   src,
		})
		e.Session.Log().Info("relationship discovered", "from",
			name, "relation", a.rtype, "to", ip.Address.String(),
			slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}
