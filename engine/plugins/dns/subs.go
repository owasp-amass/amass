// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"time"

	"github.com/caffix/stringset"
	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/resolve/utils"
	"golang.org/x/net/publicsuffix"
)

type subsQtypes struct {
	Qtype uint16
	Rtype string
}

type subsSession struct {
	session et.Session
	strset  *stringset.Set
}

type dnsSubs struct {
	sync.Mutex
	name      string
	types     []subsQtypes
	done      chan struct{}
	sessNames map[string]*subsSession
	plugin    *dnsPlugin
}

type relSubs struct {
	rtype  string
	alias  *dbt.Entity
	target *dbt.Entity
}

func NewSubs(p *dnsPlugin) *dnsSubs {
	return &dnsSubs{
		name: p.name + "-Subdomains",
		types: []subsQtypes{
			{Qtype: dns.TypeNS, Rtype: "ns_record"},
			{Qtype: dns.TypeMX, Rtype: "mx_record"},
			//{Qtype: dns.TypeSOA, Rtype: "soa_record"},
			//{Qtype: dns.TypeSPF, Rtype: "spf_record"},
		},
		done:      make(chan struct{}),
		sessNames: make(map[string]*subsSession),
		plugin:    p,
	}
}

func (d *dnsSubs) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	if !support.HasDNSRecordType(e, int(dns.TypeA)) && !support.HasDNSRecordType(e, int(dns.TypeAAAA)) {
		return nil
	}

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", d.plugin.name)
	if err != nil {
		return err
	}

	if dom := d.registeredDomainName(e); dom != "" {
		if names := d.traverse(e, dom, e.Entity, since); len(names) > 0 {
			d.process(e, names)
		}
	}
	return nil
}

func (d *dnsSubs) registeredDomainName(e *et.Event) string {
	fqdn := e.Entity.Asset.(*oamdns.FQDN)

	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf > 0 && a != nil {
		if fqdn, ok := a.(*oamdns.FQDN); ok {
			return fqdn.Name
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	var rels []*dbt.Edge
	// allow name servers and mail servers to be investigated like in-scope assets
	if edges, err := e.Session.DB().IncomingEdges(ctx, e.Entity, time.Time{}, "dns_record"); err == nil && len(edges) > 0 {
		for _, edge := range edges {
			if r, ok := edge.Relation.(*oamdns.BasicDNSRelation); ok && r.Header.RRType == int(dns.TypeNS) {
				rels = append(rels, edge)
			} else if r, ok := edge.Relation.(*oamdns.PrefDNSRelation); ok && r.Header.RRType == int(dns.TypeMX) {
				rels = append(rels, edge)
			}
		}
	}

	var inscope bool
	for _, r := range rels {
		from, err := e.Session.DB().FindEntityById(ctx, r.FromEntity.ID)
		if err != nil {
			continue
		}
		if f, ok := from.Asset.(*oamdns.FQDN); ok && from != nil {
			if _, conf := e.Session.Scope().IsAssetInScope(f, 0); conf > 0 {
				inscope = true
				break
			}
		}
	}
	if inscope {
		if dom, err := publicsuffix.EffectiveTLDPlusOne(fqdn.Name); err == nil {
			return dom
		}
	}
	return ""
}

func (d *dnsSubs) traverse(e *et.Event, dom string, fqdn *dbt.Entity, since time.Time) []*relSubs {
	var alias []*relSubs

	dlabels := strings.Split(dom, ".")
	dlen := len(dlabels)
	if dlen < 2 {
		return alias
	}

	sub := fqdn.Asset.Key()
	for labels := strings.Split(sub, "."); dlen <= len(labels); labels = labels[1:] {
		sub = strings.TrimSpace(strings.Join(labels, "."))

		// no need to check subdomains already evaluated
		if d.fqdnAvailable(e, sub) {
			results := d.lookup(e, sub, since)
			if len(results) == 0 {
				results = d.query(e, sub)
			}
			alias = append(alias, results...)
		}
	}

	return alias
}

func (d *dnsSubs) lookup(e *et.Event, subdomain string, since time.Time) []*relSubs {
	var alias []*relSubs

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	fqdn, err := e.Session.DB().FindOneEntityByContent(ctx, oam.FQDN, time.Time{}, dbt.ContentFilters{
		"name": subdomain,
	})
	if err != nil || fqdn == nil {
		return alias
	}

	n := fqdn.Asset.Key()
	// Check for NS records within the since period
	if assets := d.plugin.lookupWithinTTL(e.Session, n, oam.FQDN, since, oam.BasicDNSRelation, 2); len(assets) > 0 {
		for _, a := range assets {
			alias = append(alias, &relSubs{rtype: "dns_record", alias: fqdn, target: a})
		}
	}
	// Check for MX records within the since period
	if assets := d.plugin.lookupWithinTTL(e.Session, n, oam.FQDN, since, oam.PrefDNSRelation, 15); len(assets) > 0 {
		for _, a := range assets {
			alias = append(alias, &relSubs{rtype: "dns_record", alias: fqdn, target: a})
		}
	}
	return alias
}

func (d *dnsSubs) query(e *et.Event, subdomain string) []*relSubs {
	apex := true
	var alias []*relSubs

	for i, t := range d.types {
		if rr, err := support.PerformQuery(subdomain, t.Qtype); err == nil && len(rr) > 0 {
			if records := d.store(e, subdomain, rr); len(records) > 0 {
				alias = append(alias, records...)
			}
		} else if i == 0 {
			// do not continue if we failed to obtain the NS record
			apex = false
			break
		}
	}

	if !apex {
		return alias
	}

	srvs := NamesByTier(Tier3)
	rch := make(chan []*relSubs, len(srvs))
	defer close(rch)

	for _, name := range srvs {
		go func(label, sub string, ch chan []*relSubs) {
			n := name + "." + subdomain

			var results []*relSubs
			if rr, err := support.PerformQuery(n, dns.TypeSRV); err == nil && len(rr) > 0 {
				if records := d.store(e, n, rr); len(records) > 0 {
					results = append(results, records...)
				}
			}
			ch <- results
		}(name, subdomain, rch)
	}

	for range len(srvs) {
		answers := <-rch
		alias = append(alias, answers...)
	}

	return alias
}

func (d *dnsSubs) store(e *et.Event, name string, rr []dns.RR) []*relSubs {
	var alias []*relSubs

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	fqdn, err := e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name})
	if err != nil || fqdn == nil {
		return alias
	}

	for _, record := range rr {
		var a *dbt.Entity
		var edge *dbt.Edge

		if record.Header().Rrtype == dns.TypeNS {
			data := utils.RemoveLastDot((record.(*dns.NS)).Ns)

			a, err = e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: data})
			if err == nil && a != nil {
				edge, err = e.Session.DB().CreateEdge(ctx, &dbt.Edge{
					Relation: &oamdns.BasicDNSRelation{
						Name: "dns_record",
						Header: oamdns.RRHeader{
							RRType: int(record.Header().Rrtype),
							Class:  int(record.Header().Class),
							TTL:    int(record.Header().Ttl),
						},
					},
					FromEntity: fqdn,
					ToEntity:   a,
				})
			}
		} else if record.Header().Rrtype == dns.TypeMX {
			data := utils.RemoveLastDot((record.(*dns.MX)).Mx)

			a, err = e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: data})
			if err == nil && a != nil {
				edge, err = e.Session.DB().CreateEdge(ctx, &dbt.Edge{
					Relation: &oamdns.PrefDNSRelation{
						Name: "dns_record",
						Header: oamdns.RRHeader{
							RRType: int(record.Header().Rrtype),
							Class:  int(record.Header().Class),
							TTL:    int(record.Header().Ttl),
						},
						Preference: int((record.(*dns.MX)).Preference),
					},
					FromEntity: fqdn,
					ToEntity:   a,
				})
			}
		} else {
			continue
		}

		if err == nil && edge != nil {
			alias = append(alias, &relSubs{rtype: "dns_record", alias: fqdn, target: a})
			_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
				Source:     d.plugin.source.Name,
				Confidence: d.plugin.source.Confidence,
			})
		} else {
			e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}

	if len(alias) > 0 {
		d.plugin.addApex(name, fqdn)
	}
	return alias
}

func (d *dnsSubs) process(e *et.Event, results []*relSubs) {
	for _, finding := range results {
		fname, ok := finding.alias.Asset.(*oamdns.FQDN)
		if !ok || fname == nil {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    fname.Name,
			Entity:  finding.alias,
			Session: e.Session,
		})

		tname, ok := finding.target.Asset.(*oamdns.FQDN)
		if !ok || tname == nil {
			continue
		}

		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    tname.Name,
			Entity:  finding.target,
			Session: e.Session,
		})

		e.Session.Log().Info("relationship discovered", "from", fname.Name, "relation",
			finding.rtype, "to", tname.Name, slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}

func (d *dnsSubs) fqdnAvailable(e *et.Event, fqdn string) bool {
	d.Lock()
	defer d.Unlock()

	id := e.Session.ID().String()
	if _, found := d.sessNames[id]; !found {
		d.sessNames[id] = &subsSession{
			session: e.Session,
			strset:  stringset.New(),
		}
	}

	var avail bool
	if !d.sessNames[id].strset.Has(fqdn) {
		avail = true
		d.sessNames[id].strset.Insert(fqdn)
	}
	return avail
}

func (d *dnsSubs) releaseSessions() {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
loop:
	for {
		select {
		case <-d.done:
			break loop
		case <-t.C:
			d.Lock()
			var ids []string
			for id, s := range d.sessNames {
				if s.session.Done() {
					ids = append(ids, id)
					s.strset.Close()
				}
			}
			for _, id := range ids {
				delete(d.sessNames, id)
			}
			d.Unlock()
		}
	}

	d.Lock()
	for _, sess := range d.sessNames {
		sess.strset.Close()
	}
	d.Unlock()
}
