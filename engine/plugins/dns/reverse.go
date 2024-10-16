// Copyright © by Jeff Foley 2017-2024. All rights reserved.
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
	amassnet "github.com/owasp-amass/amass/v4/utils/net"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/domain"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/owasp-amass/resolve"
)

type dnsReverse struct {
	name   string
	plugin *dnsPlugin
}

type relRev struct {
	ipFQDN *dbt.Asset
	target *dbt.Asset
}

func NewReverse(p *dnsPlugin) *dnsReverse {
	return &dnsReverse{
		name:   p.name + "-Reverse",
		plugin: p,
	}
}

func (d *dnsReverse) check(e *et.Event) error {
	ip, ok := e.Asset.Asset.(*oamnet.IPAddress)
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
	reverse = resolve.RemoveLastDot(reverse)

	src := support.GetSource(e.Session, d.plugin.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	ptr := d.createPTRAlias(e, reverse, src)
	if ptr == nil {
		return nil
	}
	e.Session.Cache().SetAsset(ptr)

	since, err := support.TTLStartTime(e.Session.Config(), "IPAddress", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	var rev []*relRev
	if support.AssetMonitoredWithinTTL(e.Session, e.Asset, src, since) {
		rev = append(rev, d.lookup(e, ptr, since)...)
	} else {
		rev = append(rev, d.query(e, addrstr, ptr, src)...)
		support.MarkAssetMonitored(e.Session, ptr, src)
	}

	if len(rev) > 0 {
		d.process(e, rev, src)

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

func (d *dnsReverse) lookup(e *et.Event, fqdn *dbt.Asset, since time.Time) []*relRev {
	var rev []*relRev

	n, ok := fqdn.Asset.(*domain.FQDN)
	if !ok || n == nil {
		return rev
	}

	if assets := d.plugin.lookupWithinTTL(e.Session, n.Name, "FQDN", since, "ptr_record"); len(assets) > 0 {
		for _, a := range assets {
			rev = append(rev, &relRev{ipFQDN: fqdn, target: a})
		}
	}

	return rev
}

func (d *dnsReverse) query(e *et.Event, ipstr string, ptr, src *dbt.Asset) []*relRev {
	var rev []*relRev

	if rr, err := support.PerformQuery(ipstr, dns.TypePTR); err == nil {
		if records := d.store(e, ptr, src, rr); len(records) > 0 {
			rev = append(rev, records...)
		}
	}
	return rev
}

func (d *dnsReverse) store(e *et.Event, ptr, src *dbt.Asset, rr []*resolve.ExtractedAnswer) []*relRev {
	var rev []*relRev

	var passed bool
	// additional validation of the PTR record
	for _, record := range rr {
		if record.Type != dns.TypePTR {
			continue
		}

		data := strings.ToLower(strings.TrimSpace(record.Data))
		if name := support.ScrapeSubdomainNames(data); len(name) == 1 && name[0] == data {
			passed = true
			break
		}
	}
	if !passed {
		return rev
	}

	done := make(chan struct{}, 1)
	support.AppendToDBQueue(func() {
		defer func() { done <- struct{}{} }()

		if e.Session.Done() {
			return
		}

		for _, record := range rr {
			if record.Type != dns.TypePTR {
				continue
			}

			if t, err := e.Session.DB().Create(ptr, "ptr_record", &domain.FQDN{Name: record.Data}); err == nil {
				if t != nil {
					rev = append(rev, &relRev{ipFQDN: ptr, target: t})
					_, _ = e.Session.DB().Link(t, "source", src)
				}
			} else {
				e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			}
		}
	})
	<-done
	close(done)
	return rev
}

func (d *dnsReverse) createPTRAlias(e *et.Event, name string, datasrc *dbt.Asset) *dbt.Asset {
	done := make(chan *dbt.Asset, 1)
	defer close(done)

	support.AppendToDBQueue(func() {
		if e.Session.Done() {
			done <- nil
			return
		}

		ptr, err := e.Session.DB().Create(nil, "", &domain.FQDN{Name: name})
		if err == nil && ptr != nil {
			_, _ = e.Session.DB().Link(ptr, "source", datasrc)
		}
		done <- ptr
	})

	return <-done
}

func (d *dnsReverse) process(e *et.Event, rev []*relRev, src *dbt.Asset) {
	now := time.Now()

	for _, r := range rev {
		ip := r.ipFQDN.Asset.(*domain.FQDN)
		target := r.target.Asset.(*domain.FQDN)

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    target.Name,
			Asset:   r.target,
			Session: e.Session,
		})

		e.Session.Cache().SetRelation(&dbt.Relation{
			Type:      "source",
			CreatedAt: now,
			LastSeen:  now,
			FromAsset: r.target,
			ToAsset:   src,
		})

		if ptr, hit := e.Session.Cache().GetAsset(&domain.FQDN{Name: ip.Name}); hit && ptr != nil {
			e.Session.Cache().SetRelation(&dbt.Relation{
				Type:      "ptr_record",
				CreatedAt: now,
				LastSeen:  now,
				FromAsset: ptr,
				ToAsset:   r.target,
			})

			e.Session.Log().Info("relationship discovered", "from",
				ip.Name, "relation", "ptr_record", "to", target.Name,
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}
}
