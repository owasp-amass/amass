// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// SOA administrator mailboxes and SPF address ranges (engine/plugins/dns).

// rrTypeSOA is the SOA record type.
const rrTypeSOA = 6

// soaZone is a registered domain's SOA as stored: its administrator mailbox
// and primary name server.
type soaZone struct {
	mailbox string
	mname   string
}

// zoneSOA reads the mailbox and primary name server a registered domain's
// SOA record names.
func zoneSOA(ctx context.Context, g graph.Graph, apexID string) soaZone {
	var z soaZone
	if edges, err := g.Edges(ctx, apexID, "out", "soa_rname", time.Time{}); err == nil && len(edges) > 0 {
		if id, err := g.GetAsset(ctx, edges[0].ToID); err == nil {
			z.mailbox = strings.ToLower(graph.ContentString(id, "id"))
		}
	}
	if edges, err := g.Edges(ctx, apexID, "out", "dns_record", time.Time{}); err == nil {
		for _, e := range edges {
			if relationRRType(e) == rrTypeSOA {
				if ns, err := g.GetAsset(ctx, e.ToID); err == nil {
					z.mname = graph.FQDNName(ns)
				}
				break
			}
		}
	}
	return z
}

// providerMailbox reports whether a zone's mailbox is its DNS host's default
// rather than its owner's: the mailbox is at the registered domain of the
// zone's primary name server, and that server is a managed-DNS provider's or
// is outside own (Namecheap, DigitalOcean and Hurricane Electric publish
// hostmaster@ their own domain for every customer zone).
func providerMailbox(z soaZone, own []string) bool {
	_, domain, ok := strings.Cut(z.mailbox, "@")
	if !ok || z.mname == "" {
		return false
	}
	if isNameServerProvider(z.mname) {
		return true
	}
	if graph.RegisteredDomain(domain) != graph.RegisteredDomain(z.mname) {
		return false
	}
	for _, d := range own {
		if HostWithin(z.mname, d) {
			return false
		}
	}
	return true
}

// soaMailboxPivot finds the other registered domains whose SOA record names
// the same administrator mailbox as one of the organization's own: the
// strong signal when the mailbox is at one of the organization's domains, the
// supporting one for an outside mailbox. A DNS host's default mailbox, and a
// mailbox more domains list than the SOA mailbox hub limit, give none.
func soaMailboxPivot(ctx context.Context, g graph.Graph, ownApexes []string, hub hubCheck,
	add func(string, string, string, ...graph.WitnessEdge)) {
	var own []string
	for _, id := range ownApexes {
		if a, err := g.GetAsset(ctx, id); err == nil && graph.FQDNName(a) != "" {
			own = append(own, graph.FQDNName(a))
		}
	}

	seen := map[string]bool{}
	for _, apexID := range ownApexes {
		edges, err := g.Edges(ctx, apexID, "out", "soa_rname", time.Time{})
		if err != nil || len(edges) == 0 || seen[edges[0].ToID] {
			continue
		}
		me := edges[0]
		seen[me.ToID] = true
		if providerMailbox(zoneSOA(ctx, g, apexID), own) {
			continue
		}
		id, err := g.GetAsset(ctx, me.ToID)
		if err != nil {
			continue
		}
		mailbox := strings.ToLower(graph.ContentString(id, "id"))
		_, domain, _ := strings.Cut(mailbox, "@")
		sig, label := SigSharedSOAMailbox, "same SOA administrator mailbox "+mailbox
		for _, d := range own {
			if domain != "" && HostWithin(domain, d) {
				sig, label = SigSOAMailboxOwn, "SOA administrator mailbox at the organization's domain: "+mailbox
				break
			}
		}

		others, err := g.Edges(ctx, me.ToID, "in", "soa_rname", time.Time{})
		if err != nil || hub.over(mailbox, len(others), false) {
			continue
		}
		ownW := graph.WitnessEdge{EdgeID: me.ID, Label: "soa_rname", RelationType: me.Type,
			FromID: me.FromID, FromType: "FQDN", ToID: me.ToID, ToType: "Identifier"}
		for _, oe := range others {
			if oe.FromID == apexID {
				continue
			}
			other, err := g.GetAsset(ctx, oe.FromID)
			if err != nil {
				continue
			}
			if providerMailbox(zoneSOA(ctx, g, oe.FromID), own) {
				continue
			}
			apex := graph.RegisteredDomain(graph.FQDNName(other))
			if apex == "" {
				continue
			}
			otherW := graph.WitnessEdge{EdgeID: oe.ID, Label: "soa_rname", RelationType: oe.Type,
				FromID: oe.FromID, FromType: "FQDN", ToID: oe.ToID, ToType: "Identifier"}
			add(apex, sig, label, ownW, otherW)
		}
	}
}

// spfRanges adds the netblocks a registered domain's SPF record authorizes
// to send its mail: the supporting spf-declared-range signal. A single
// address counts through the stored netblock that contains it. Netblocks a
// cloud provider publishes as its own are skipped: they are the provider's
// shared sending infrastructure.
func spfRanges(ctx context.Context, g graph.Graph, apexID, name string,
	add func(string, string, string, string, ...graph.WitnessEdge)) {
	edges, err := g.Edges(ctx, apexID, "out", "spf_authorizes", time.Time{})
	if err != nil {
		return
	}
	label := "declared as a mail sender in the SPF record of a domain registered to: " + name
	for _, e := range edges {
		a, err := g.GetAsset(ctx, e.ToID)
		if err != nil {
			continue
		}
		spfW := graph.WitnessEdge{EdgeID: e.ID, Label: "spf_authorizes", RelationType: e.Type,
			FromID: e.FromID, FromType: "FQDN", ToID: e.ToID, ToType: a.Type}
		var blocks []graph.Asset
		switch a.Type {
		case "Netblock":
			blocks = []graph.Asset{a}
		case "IPAddress":
			if cs, err := g.Edges(ctx, a.ID, "in", "contains", time.Time{}); err == nil {
				for _, c := range cs {
					if nb, err := g.GetAsset(ctx, c.FromID); err == nil && nb.Type == "Netblock" {
						blocks = append(blocks, nb)
					}
				}
			}
		}
		for _, nb := range blocks {
			if p, err := g.Edges(ctx, nb.ID, "out", "provider", time.Time{}); err == nil && len(p) > 0 {
				continue
			}
			add("Netblock", graph.ContentString(nb, "cidr"), SigSPFDeclaredRange, label, spfW)
		}
	}
}
