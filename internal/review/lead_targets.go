// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"time"

	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
)

// LeadTargets are a run's own targets. A document lead counts as confirmed
// only when the engine ties it to one of them: the lead itself is a target
// asset the engine linked to others, or a path of stored relations joins the
// lead to a target asset. Without targets, any relation or another source
// confirms a lead.
type LeadTargets struct {
	// Domains are registered domains; an FQDN at or under one is a target.
	Domains []string
	// Prefixes are address ranges; an IP address or netblock inside one is a
	// target (a single address is a /32 or /128).
	Prefixes []netip.Prefix
	// ASNs are autonomous system numbers.
	ASNs []int
}

// NewLeadTargets returns the targets the assets name: an FQDN's domain, an
// address or netblock range, an autonomous system. Other assets name none.
func NewLeadTargets(assets []oam.Asset) LeadTargets {
	var t LeadTargets
	for _, a := range assets {
		switch v := a.(type) {
		case oamdns.FQDN:
			if d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(v.Name)), "."); d != "" {
				t.Domains = append(t.Domains, d)
			}
		case oamnet.IPAddress:
			addr := v.Address.Unmap()
			t.Prefixes = append(t.Prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		case oamnet.Netblock:
			t.Prefixes = append(t.Prefixes, v.CIDR.Masked())
		case oamnet.AutonomousSystem:
			t.ASNs = append(t.ASNs, v.Number)
		}
	}
	return t
}

// Empty reports whether no target is known.
func (t LeadTargets) Empty() bool {
	return len(t.Domains) == 0 && len(t.Prefixes) == 0 && len(t.ASNs) == 0
}

// matches reports whether an asset is one of the targets.
func (t LeadTargets) matches(a oam.Asset) bool {
	// a lead submitted to a run is a value; a stored asset read back is a
	// pointer
	switch v := a.(type) {
	case oamdns.FQDN:
		return t.matches(&v)
	case oamnet.IPAddress:
		return t.matches(&v)
	case oamnet.Netblock:
		return t.matches(&v)
	case oamnet.AutonomousSystem:
		return t.matches(&v)
	}

	switch v := a.(type) {
	case *oamdns.FQDN:
		name := strings.TrimSuffix(strings.ToLower(v.Name), ".")
		return slices.ContainsFunc(t.Domains, func(d string) bool {
			return name == d || strings.HasSuffix(name, "."+d)
		})
	case *oamnet.IPAddress:
		return slices.ContainsFunc(t.Prefixes, func(p netip.Prefix) bool { return p.Contains(v.Address.Unmap()) })
	case *oamnet.Netblock:
		return slices.ContainsFunc(t.Prefixes, func(p netip.Prefix) bool {
			return p.Bits() <= v.CIDR.Bits() && p.Contains(v.CIDR.Addr().Unmap())
		})
	case *oamnet.AutonomousSystem:
		return slices.Contains(t.ASNs, v.Number)
	}
	return false
}

// Bounds of the walk from a lead toward the run's targets. A phone reaches
// the organization's domain in four steps (phone, contact record,
// organization, website URL, domain); an office in three.
const (
	tieDepth    = 4
	tieMaxSeen  = 300
	tieMaxEdges = 100
)

// tieSkipTypes are not walked through: a funds transfer joins its payer and
// recipient, so walking through transfers ties unrelated organizations that
// were paid by the same agency.
var tieSkipTypes = []oam.AssetType{oam.FundsTransfer}

// leadEdgeReader is what the walk reads.
type leadEdgeReader interface {
	FindEntityById(ctx context.Context, id string) (*dbt.Entity, error)
	IncomingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error)
	OutgoingEdges(ctx context.Context, entity *dbt.Entity, since time.Time, labels ...string) ([]*dbt.Edge, error)
}

// tiedToTargets reports whether the engine tied a lead to the run's targets:
// the lead is a target asset with at least one relation (first, the lead's
// relations), or a target asset is within tieDepth relations of it. An asset with more than tieMaxEdges
// relations (a shared provider, a large registry) is checked but not walked
// through, so a hub does not tie everything to everything.
func tiedToTargets(ctx context.Context, w leadEdgeReader, lead *dbt.Entity, first []*dbt.Edge,
	t LeadTargets) bool {
	if lead == nil || lead.Asset == nil {
		return false
	}
	if t.matches(lead.Asset) {
		return len(first) > 0
	}

	seen := map[string]bool{lead.ID: true}
	frontier := []*dbt.Entity{lead}
	firstEdges := map[string][]*dbt.Edge{lead.ID: first}
	for depth := 0; depth < tieDepth && len(frontier) > 0; depth++ {
		var next []*dbt.Entity
		for _, ent := range frontier {
			if ctx.Err() != nil {
				return false
			}
			edges, ok := firstEdges[ent.ID]
			if !ok {
				edges = entityEdges(ctx, w, ent)
			}
			if len(edges) > tieMaxEdges && ent.ID != lead.ID {
				continue
			}
			for _, e := range edges {
				if e == nil {
					continue
				}
				for _, end := range []*dbt.Entity{e.FromEntity, e.ToEntity} {
					if end == nil || seen[end.ID] || len(seen) >= tieMaxSeen {
						continue
					}
					seen[end.ID] = true
					other := end
					if other.Asset == nil {
						found, err := w.FindEntityById(ctx, end.ID)
						if err != nil || found == nil || found.Asset == nil {
							continue
						}
						other = found
					}
					if t.matches(other.Asset) {
						return true
					}
					if !slices.Contains(tieSkipTypes, other.Asset.AssetType()) {
						next = append(next, other)
					}
				}
			}
		}
		frontier = next
	}
	return false
}
