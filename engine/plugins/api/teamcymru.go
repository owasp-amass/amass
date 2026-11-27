// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/sessions"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"golang.org/x/time/rate"
)

// teamCymru maps an address to its covering prefix and announcing AS using the
// Team Cymru IP-to-ASN DNS service (origin.asn.cymru.com / origin6.asn.cymru.com),
// a TXT lookup designed for automated use. It corroborates BGP.Tools and BGPView
// on the shared AutonomousSystem/Netblock/announces assets, tagged with Team
// Cymru's own SourceProperty. A TXT answer is "ASN[ ASN...] | prefix | CC |
// registry | allocated"; a prefix can be multi-origin, so every listed AS is
// recorded as announcing it.
type teamCymru struct {
	name   string
	log    *slog.Logger
	rlimit *rate.Limiter
	source *et.Source
}

func NewTeamCymru() et.Plugin {
	return &teamCymru{
		name:   "Team-Cymru",
		rlimit: rate.NewLimiter(rate.Every(time.Second), 1),
		source: &et.Source{Name: "Team-Cymru", Confidence: 90},
	}
}

func (c *teamCymru) Name() string { return c.name }

func (c *teamCymru) Start(r et.Registry) error {
	c.log = r.Log().WithGroup("plugin").With("name", c.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       c,
		Name:         c.name + "-IP-Handler",
		Position:     5,
		MaxInstances: support.MidHandlerInstances,
		Transforms:   []string{string(oam.Netblock), string(oam.AutonomousSystem)},
		EventType:    oam.IPAddress,
		Callback:     c.check,
	}); err != nil {
		return err
	}

	c.log.Info("Plugin started")
	return nil
}

func (c *teamCymru) Stop() { c.log.Info("Plugin stopped") }

func (c *teamCymru) check(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok {
		return errors.New("failed to extract the IPAddress asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(),
		string(oam.IPAddress), string(oam.Netblock), c.name)
	if err != nil {
		return err
	}
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, c.source, since) {
		return nil
	}
	// the service answers only for routed addresses, and a failed query is
	// retried by the resolver pool, so private, shared and other reserved
	// addresses are never asked about
	if reserved, _ := amassnet.IsReservedAddress(ip.Address.String()); reserved {
		return nil
	}
	if c.covered(e, ip.Address) {
		return nil
	}

	name := cymruName(ip.Address)
	if name == "" {
		return nil
	}

	_ = support.WaitLimit(e.Session.Ctx(), c.rlimit)
	// the name is built for the service, not found in a target's zone, so
	// the wildcard check that guards discovered names does not apply
	rr, err := support.PerformQueryNoWildcard(e.Session.Ctx(), name, dns.TypeTXT)
	if errors.Is(err, support.ErrNameDoesNotExist) || errors.Is(err, support.ErrNoRecordOfThisType) {
		// the service has no route for the address: do not ask again
		// within the TTL
		support.MarkAssetMonitored(e.Session, e.Entity, c.source)
		return nil
	}
	if err != nil || len(rr) == 0 {
		return nil
	}

	asns, prefix := parseCymru(rr)
	if prefix == "" || len(asns) == 0 {
		return nil
	}

	support.MarkAssetMonitored(e.Session, e.Entity, c.source)

	nb := c.storeNetblock(e, prefix)
	if nb == nil {
		return nil
	}
	if _, ipnet, err := net.ParseCIDR(prefix); err == nil {
		_ = e.Session.CIDRanger().Insert(&sessions.CIDRangerEntry{Net: ipnet, ASN: asns[0], Src: c.source})
	}
	c.edge(e, nb, e.Entity, "contains")
	for _, asn := range asns {
		if as := c.storeAutnum(e, asn); as != nil {
			c.edge(e, as, nb, "announces")
			c.dispatch(e, as, "AS"+as.Asset.Key())
		}
	}
	c.dispatch(e, nb, nb.Asset.Key())

	e.Session.Log().Info("IP-to-ASN resolved", "ip", ip.Address.String(), "prefix", prefix, "asns", asns,
		slog.Group("plugin", "name", c.name, "handler", c.name+"-IP-Handler"))
	return nil
}

// covered links the address to the prefix this source resolved for another
// address of the session, when one contains it, without asking the service
// again: the addresses of a target cluster in a few prefixes. Only this
// source's own answers count, so it still corroborates the other routing
// sources. The most specific prefix is used; an address in a more specific
// prefix not yet seen is attributed to the covering one, as the session's
// other routing lookups do.
func (c *teamCymru) covered(e *et.Event, addr netip.Addr) bool {
	entries, err := e.Session.CIDRanger().ContainingNetworks(net.IP(addr.Unmap().AsSlice()))
	if err != nil {
		return false
	}

	var best *sessions.CIDRangerEntry
	for _, entry := range entries {
		ce, ok := entry.(*sessions.CIDRangerEntry)
		if !ok || ce.Src == nil || ce.Src.Name != c.source.Name {
			continue
		}
		if ones, _ := ce.Net.Mask.Size(); best == nil || ones > maskOnes(best) {
			best = ce
		}
	}
	if best == nil {
		return false
	}

	nb := c.storeNetblock(e, best.Net.String())
	if nb == nil {
		return false
	}
	c.edge(e, nb, e.Entity, "contains")
	support.MarkAssetMonitored(e.Session, e.Entity, c.source)
	return true
}

func maskOnes(ce *sessions.CIDRangerEntry) int {
	ones, _ := ce.Net.Mask.Size()
	return ones
}

// cymruName builds the Team Cymru origin query name for an address: the octets
// reversed under origin.asn.cymru.com (IPv4) or the nibbles reversed under
// origin6.asn.cymru.com (IPv6).
func cymruName(addr netip.Addr) string {
	addr = addr.Unmap()
	switch {
	case addr.Is4():
		o := addr.As4()
		return fmt.Sprintf("%d.%d.%d.%d.origin.asn.cymru.com", o[3], o[2], o[1], o[0])
	case addr.Is6():
		b := addr.As16()
		var sb strings.Builder
		for i := len(b) - 1; i >= 0; i-- {
			fmt.Fprintf(&sb, "%x.%x.", b[i]&0xf, b[i]>>4)
		}
		sb.WriteString("origin6.asn.cymru.com")
		return sb.String()
	default:
		return ""
	}
}

// parseCymru reads the announcing ASNs and the BGP prefix from a Team Cymru TXT
// answer: "ASN[ ASN...] | prefix | CC | registry | allocated".
func parseCymru(rr []dns.RR) ([]int, string) {
	for _, record := range rr {
		txt, ok := record.(*dns.TXT)
		if !ok {
			continue
		}
		fields := strings.Split(strings.Join(txt.Txt, ""), "|")
		if len(fields) < 2 {
			continue
		}

		var asns []int
		for _, a := range strings.Fields(strings.TrimSpace(fields[0])) {
			var n int
			if _, err := fmt.Sscanf(a, "%d", &n); err == nil && n > 0 {
				asns = append(asns, n)
			}
		}
		prefix := strings.TrimSpace(fields[1])
		if _, err := netip.ParsePrefix(prefix); err != nil {
			continue
		}
		if len(asns) > 0 {
			return asns, prefix
		}
	}
	return nil, ""
}

func (c *teamCymru) storeNetblock(e *et.Event, prefix string) *dbt.Entity {
	pfx, err := netip.ParsePrefix(prefix)
	if err != nil {
		return nil
	}
	ntype := "IPv4"
	if pfx.Addr().Is6() {
		ntype = "IPv6"
	}

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	nb, err := e.Session.DB().CreateAsset(ctx, &oamnet.Netblock{CIDR: pfx, Type: ntype})
	if err != nil || nb == nil {
		return nil
	}
	support.AddSource(ctx, e.Session, nb, c.source)
	return nb
}

func (c *teamCymru) storeAutnum(e *et.Event, asn int) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	as, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: asn})
	if err != nil || as == nil {
		return nil
	}
	support.AddSource(ctx, e.Session, as, c.source)
	return as
}

func (c *teamCymru) edge(e *et.Event, from, to *dbt.Entity, label string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	_, _ = support.Relate(ctx, e.Session, from, &general.SimpleRelation{Name: label}, to, c.source)
}

func (c *teamCymru) dispatch(e *et.Event, entity *dbt.Entity, name string) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    name,
		Entity:  entity,
		Session: e.Session,
	})
}
