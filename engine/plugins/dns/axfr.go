// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/resolve/utils"
)

const (
	// maxAXFRRecords caps how many records a single zone transfer reads, so a
	// very large or hostile zone cannot exhaust memory.
	maxAXFRRecords = 50000
	// axfrPort is the TCP port a zone transfer is attempted on.
	axfrPort = "53"
)

// queryAXFR attempts a DNS zone transfer (AXFR) against each authoritative
// nameserver of the apex. A nameserver that answers a transfer exposes every
// record in the zone, which is both a notable misconfiguration and a rich
// source of subdomains. It runs during active enumeration only.
func (d *dnsSubs) queryAXFR(e *et.Event, apex *dbt.Entity, name string) {
	if apex == nil || !e.Session.Config().Active {
		return
	}

	ns, err := support.PerformQuery(e.Session.Ctx(), name, dns.TypeNS)
	if err != nil || len(ns) == 0 {
		return
	}

	seen := make(map[string]bool)
	for _, rr := range ns {
		record, ok := rr.(*dns.NS)
		if !ok {
			continue
		}
		server := utils.RemoveLastDot(record.Ns)
		if server == "" || seen[server] {
			continue
		}
		seen[server] = true
		d.attemptAXFR(e, apex, name, server)
	}
}

// attemptAXFR resolves a nameserver and tries a zone transfer against each of
// its addresses, stopping at the first that answers.
func (d *dnsSubs) attemptAXFR(e *et.Event, apex *dbt.Entity, zone, server string) {
	var addrs []string
	for _, t := range []uint16{dns.TypeA, dns.TypeAAAA} {
		rr, err := support.PerformQuery(e.Session.Ctx(), server, t)
		if err != nil {
			continue
		}
		for _, r := range rr {
			switch v := r.(type) {
			case *dns.A:
				addrs = append(addrs, v.A.String())
			case *dns.AAAA:
				addrs = append(addrs, v.AAAA.String())
			}
		}
	}

	for _, addr := range addrs {
		records, ok := transferZone(e.Session.Ctx(), zone, net.JoinHostPort(addr, axfrPort))
		if !ok {
			continue
		}
		d.recordZoneTransfer(e, apex, zone, server)
		d.ingestZone(e, apex, zone, records)
		e.Session.Log().Info("zone transfer succeeded", "zone", zone, "nameserver", server,
			"records", len(records), slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
		return
	}
}

// transferZone performs the AXFR against dialAddr (host:port) and returns the
// records received. It reports success only for a complete transfer with no
// error on the wire, so a refusal or a server that sends an error partway is
// not mistaken for an exposure. The transfer takes the session's active
// route, with a longer wait through a proxy.
func transferZone(ctx context.Context, zone, dialAddr string) ([]dns.RR, bool) {
	m := new(dns.Msg)
	m.SetAxfr(dns.Fqdn(zone))

	c, err := amassnet.NewActiveDialContext(5*time.Second)(ctx, "tcp", dialAddr)
	if err != nil {
		return nil, false
	}

	t := &dns.Transfer{Conn: &dns.Conn{Conn: c}, ReadTimeout: amassnet.ActiveTimeout(ctx, 10*time.Second)}
	defer func() { _ = t.Close() }()

	ch, err := t.In(m, dialAddr)
	if err != nil {
		return nil, false
	}

	var records []dns.RR
	ok := true
	for env := range ch {
		if env.Error != nil {
			ok = false
			continue // keep draining so the transfer goroutine can finish
		}
		if len(records) < maxAXFRRecords {
			records = append(records, env.RR...)
		}
	}
	if !ok || len(records) == 0 {
		return nil, false
	}
	return records, true
}

// recordZoneTransfer notes, on the zone apex, that a nameserver answered a
// zone transfer, so the exposure can be reported later without a live scan.
func (d *dnsSubs) recordZoneTransfer(e *et.Event, apex *dbt.Entity, zone, server string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	if _, err := e.Session.DB().CreateEntityProperty(ctx, apex, &general.SimpleProperty{
		PropertyName:  "zone_transfer",
		PropertyValue: server,
	}); err != nil {
		e.Session.Log().Error("failed to store the zone transfer exposure", "zone", zone, "nameserver", server,
			slog.Group("plugin", "name", d.plugin.name, "handler", d.name))
	}
}

// ingestZone turns the owner names of a transferred zone into in-scope FQDN
// assets and dispatches them, so the rest of the pipeline resolves and stores
// them as it would any other discovered name. Each name is linked below the
// apex, as the apex handler links names that resolve, so that a name appears
// in the controlled footprint even before (or without) a DNS record of its
// own: the zone transfer is the evidence it was discovered.
func (d *dnsSubs) ingestZone(e *et.Event, apex *dbt.Entity, zone string, records []dns.RR) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	seen := make(map[string]bool)
	for _, rr := range records {
		name := strings.ToLower(utils.RemoveLastDot(rr.Header().Name))
		if name == "" || seen[name] || !nameInZone(name, zone) {
			continue
		}
		seen[name] = true

		fqdn := &oamdns.FQDN{Name: name}
		if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
			continue
		}

		entity, err := e.Session.DB().CreateAsset(ctx, fqdn)
		if err != nil || entity == nil {
			continue
		}
		support.AddSource(ctx, e.Session, entity, d.plugin.source)
		d.linkBelow(e, apex, entity)
		_ = e.Dispatcher.DispatchEvent(&et.Event{
			Name:    name,
			Entity:  entity,
			Session: e.Session,
		})
	}
}

// nameInZone reports whether name is the zone apex or a name below it, so a
// transfer cannot seed names belonging to an unrelated zone.
func nameInZone(name, zone string) bool {
	zone = strings.ToLower(strings.TrimSuffix(zone, "."))
	name = strings.ToLower(strings.TrimSuffix(name, "."))
	return name == zone || strings.HasSuffix(name, "."+zone)
}
