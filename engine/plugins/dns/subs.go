// Copyright © by Jeff Foley 2017-2026. All rights reserved.
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
	// failures counts, by apex, the probes below it that failed outright
	failures map[string]int
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
			// the SOA record is asked for once per apex (querySOA)
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

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
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

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 3*time.Second)
	defer cancel()

	ents, err := e.Session.DB().FindEntitiesByContent(ctx, oam.FQDN, time.Time{}, 1, dbt.ContentFilters{
		"name": subdomain,
	})
	if err != nil {
		return alias
	}
	fqdn := ents[0]

	// Check for NS records within the since period
	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, oam.FQDN, since, d.plugin.source, oam.BasicDNSRelation, 2); len(assets) > 0 {
		for _, a := range assets {
			alias = append(alias, &relSubs{rtype: "dns_record", alias: fqdn, target: a})
		}
	}
	// Check for MX records within the since period
	if assets := d.plugin.lookupWithinTTL(e.Session, fqdn, oam.FQDN, since, d.plugin.source, oam.PrefDNSRelation, 15); len(assets) > 0 {
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
		if rr, err := support.PerformQuery(e.Session.Ctx(), subdomain, t.Qtype); err == nil && len(rr) > 0 {
			if records := d.store(e, subdomain, rr); len(records) > 0 {
				alias = append(alias, records...)
			}
		} else if err == support.ErrFailedMaxDNSAttempts {
			e.Session.Log().Warn(err.Error(), "fqdn", subdomain,
				slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
			apex = i > 0
			break
		} else if i == 0 {
			// do not continue if we failed to obtain the NS record
			apex = false
			break
		}
	}

	if !apex {
		return alias
	}

	// Names asked for below the apex are linked to it, as the apex handler
	// links names that resolve, so that they are found from the domain.
	apexEnt := d.plugin.getApex(subdomain)
	d.queryPolicies(e, apexEnt, subdomain)
	d.queryCAA(e, apexEnt, subdomain)
	d.querySOA(e, apexEnt, subdomain)
	d.queryAXFR(e, apexEnt, subdomain)

	srvs := NamesByTier(Tier3)
	names := make([]string, len(srvs))
	for i, name := range srvs {
		names[i] = name + "." + subdomain
	}
	for i, rr := range d.probeAll(e, subdomain, names, dns.TypeSRV) {
		if len(rr) == 0 {
			continue
		}
		if records := d.store(e, names[i], rr); len(records) > 0 {
			d.linkBelow(e, apexEnt, records[0].alias)
			alias = append(alias, records...)
		}
	}

	return alias
}

func (d *dnsSubs) store(e *et.Event, name string, rr []dns.RR) []*relSubs {
	var alias []*relSubs

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 5*time.Second)
	defer cancel()

	// The name is stored only with a record that names another host, so an
	// SRV name whose answer cannot be kept leaves no FQDN without edges.
	var fqdn *dbt.Entity
	var apex bool
	for _, record := range rr {
		var a *dbt.Entity
		var edge *dbt.Edge
		var err error

		switch record.Header().Rrtype {
		case dns.TypeNS, dns.TypeMX:
			apex = true
		case dns.TypeSRV:
			// A target of "." says the service is not offered at this name (RFC 2782).
			if utils.RemoveLastDot((record.(*dns.SRV)).Target) == "" {
				continue
			}
		default:
			continue
		}
		if fqdn == nil {
			if fqdn, err = e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: name}); err != nil || fqdn == nil {
				return alias
			}
		}

		if record.Header().Rrtype == dns.TypeNS {
			data := utils.RemoveLastDot((record.(*dns.NS)).Ns)

			a, err = e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: data})
			if err == nil && a != nil {
				edge, err = support.Relate(ctx, e.Session, fqdn, &oamdns.BasicDNSRelation{
					Name: "dns_record",
					Header: oamdns.RRHeader{
						RRType: int(record.Header().Rrtype),
						Class:  int(record.Header().Class),
						TTL:    int(record.Header().Ttl),
					},
				}, a, d.plugin.source)
			}
		} else if record.Header().Rrtype == dns.TypeMX {
			data := utils.RemoveLastDot((record.(*dns.MX)).Mx)

			a, err = e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: data})
			if err == nil && a != nil {
				edge, err = support.Relate(ctx, e.Session, fqdn, &oamdns.PrefDNSRelation{
					Name: "dns_record",
					Header: oamdns.RRHeader{
						RRType: int(record.Header().Rrtype),
						Class:  int(record.Header().Class),
						TTL:    int(record.Header().Ttl),
					},
					Preference: int((record.(*dns.MX)).Preference),
				}, a, d.plugin.source)
			}
		} else if srv, ok := record.(*dns.SRV); ok {
			data := utils.RemoveLastDot(srv.Target)

			a, err = e.Session.DB().CreateAsset(ctx, &oamdns.FQDN{Name: data})
			if err == nil && a != nil {
				edge, err = support.Relate(ctx, e.Session, fqdn, &oamdns.SRVDNSRelation{
					Name: "dns_record",
					Header: oamdns.RRHeader{
						RRType: int(record.Header().Rrtype),
						Class:  int(record.Header().Class),
						TTL:    int(record.Header().Ttl),
					},
					Priority: int(srv.Priority),
					Weight:   int(srv.Weight),
					Port:     int(srv.Port),
				}, a, d.plugin.source)
			}
		}

		if err == nil && edge != nil {
			alias = append(alias, &relSubs{rtype: "dns_record", alias: fqdn, target: a})
		} else if err != nil {
			e.Session.Log().Error(err.Error(), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		}
	}

	// Only a name with its own NS or MX records is a zone apex; an SRV
	// name is not.
	if apex && len(alias) > 0 {
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

// sessionState returns the event's session state, creating it on first use.
// The caller holds the lock.
func (d *dnsSubs) sessionState(e *et.Event) *subsSession {
	id := e.Session.ID().String()
	s, found := d.sessNames[id]
	if !found {
		s = &subsSession{session: e.Session, strset: stringset.New(), failures: make(map[string]int)}
		d.sessNames[id] = s
	}
	return s
}

func (d *dnsSubs) fqdnAvailable(e *et.Event, fqdn string) bool {
	d.Lock()
	defer d.Unlock()

	s := d.sessionState(e)
	if s.strset.Has(fqdn) {
		return false
	}

	s.strset.Insert(fqdn)
	return true
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
