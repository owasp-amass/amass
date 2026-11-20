// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
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

	name := cymruName(ip.Address)
	if name == "" {
		return nil
	}

	_ = support.WaitLimit(e.Session.Ctx(), c.rlimit)
	rr, err := support.PerformQuery(e.Session.Ctx(), name, dns.TypeTXT)
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
	_, _ = e.Session.DB().CreateEntityProperty(ctx, nb, &general.SourceProperty{
		Source:     c.source.Name,
		Confidence: c.source.Confidence,
	})
	return nb
}

func (c *teamCymru) storeAutnum(e *et.Event, asn int) *dbt.Entity {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	as, err := e.Session.DB().CreateAsset(ctx, &oamnet.AutonomousSystem{Number: asn})
	if err != nil || as == nil {
		return nil
	}
	_, _ = e.Session.DB().CreateEntityProperty(ctx, as, &general.SourceProperty{
		Source:     c.source.Name,
		Confidence: c.source.Confidence,
	})
	return as
}

func (c *teamCymru) edge(e *et.Event, from, to *dbt.Entity, label string) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 20*time.Second)
	defer cancel()

	edge, err := e.Session.DB().CreateEdge(ctx, &dbt.Edge{
		Relation:   &general.SimpleRelation{Name: label},
		FromEntity: from,
		ToEntity:   to,
	})
	if err != nil || edge == nil {
		return
	}
	_, _ = e.Session.DB().CreateEdgeProperty(ctx, edge, &general.SourceProperty{
		Source:     c.source.Name,
		Confidence: c.source.Confidence,
	})
}

func (c *teamCymru) dispatch(e *et.Event, entity *dbt.Entity, name string) {
	_ = e.Dispatcher.DispatchEvent(&et.Event{
		Name:    name,
		Entity:  entity,
		Session: e.Session,
	})
}
