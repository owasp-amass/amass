// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"sort"
	"strconv"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// Routing security signals (engine/plugins/routing): a netblock a valid RPKI
// ROA authorizes one of the organization's ASes to announce, and the other
// netblocks the routing registry maintainer of the organization's own
// netblocks keeps.

// propIRRRoutes is the irr maintainer property the routing plugin stores: how
// many route objects the maintainer keeps. The route netblocks it keeps (at
// most max_routes) carry their origin AS (Netblock --irr_origin-->
// AutonomousSystem).
const propIRRRoutes = "irr_routes"

func routingSecurity(ctx context.Context, g graph.Graph, name string, ownAS map[string]graph.WitnessEdge,
	ownASNumbers, ownNetblocks map[string]bool,
	add func(string, string, string, string, ...graph.WitnessEdge)) {
	roaSig := "a valid ROA authorizes an AS registered to: " + name
	for _, asID := range sortedWitnessKeys(ownAS) {
		roas, err := g.Edges(ctx, asID, "in", "rpki_origin", time.Time{})
		if err != nil {
			continue
		}
		for _, re := range roas {
			nb, err := g.GetAsset(ctx, re.FromID)
			if err != nil || nb.Type != "Netblock" {
				continue
			}
			ownNetblocks[nb.ID] = true
			roaW := graph.WitnessEdge{EdgeID: re.ID, Label: "rpki_origin", RelationType: re.Type,
				FromID: re.FromID, FromType: "Netblock", ToID: re.ToID, ToType: "AutonomousSystem"}
			add("Netblock", graph.ContentString(nb, "cidr"), SigROAOwnASN, roaSig, ownAS[asID], roaW)
		}
	}

	catalog := semantics.RoutingRegistryCatalog()
	seen := map[string]bool{}
	ids := make([]string, 0, len(ownNetblocks))
	for id := range ownNetblocks {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, nbID := range ids {
		mnts, err := g.Edges(ctx, nbID, "out", "irr_maintainer", time.Time{})
		if err != nil {
			continue
		}
		for _, me := range mnts {
			if seen[me.ToID] {
				continue
			}
			seen[me.ToID] = true
			others, err := g.Edges(ctx, me.ToID, "in", "irr_maintainer", time.Time{})
			if err != nil || len(others) > catalog.MaxRoutes {
				continue
			}
			sig, ok := maintainerSignal(ctx, g, me.ToID, others, ownASNumbers, catalog)
			if !ok {
				continue
			}
			ownW := graph.WitnessEdge{EdgeID: me.ID, Label: "irr_maintainer", RelationType: me.Type,
				FromID: me.FromID, FromType: "Netblock", ToID: me.ToID, ToType: "Identifier"}
			label := "kept by the routing registry maintainer of the organization's netblocks"
			for _, oe := range others {
				if oe.FromID == nbID {
					continue
				}
				nb, err := g.GetAsset(ctx, oe.FromID)
				if err != nil || nb.Type != "Netblock" {
					continue
				}
				otherW := graph.WitnessEdge{EdgeID: oe.ID, Label: "irr_maintainer", RelationType: oe.Type,
					FromID: oe.FromID, FromType: "Netblock", ToID: oe.ToID, ToType: "Identifier"}
				add("Netblock", graph.ContentString(nb, "cidr"), sig, label, ownW, otherW)
			}
		}
	}
}

// maintainerSignal returns the signal a maintainer of the organization's
// netblocks gives its other netblocks: the strong one when every route it
// keeps (routes, its route netblocks) is originated by the organization's
// ASes, the supporting one otherwise. A maintainer keeping more than
// max_routes routes, or routes from more than max_origins ASes, gives none:
// it is an ISP, host or registry.
func maintainerSignal(ctx context.Context, g graph.Graph, id string, routes []graph.Relation,
	ownASNumbers map[string]bool, catalog semantics.RoutingRegistries) (string, bool) {
	ev, err := g.Evidence(ctx, id, 50)
	if err != nil {
		return "", false
	}
	for _, v := range propertyValues(ev, propIRRRoutes) {
		if n, err := strconv.Atoi(v); err == nil && n > catalog.MaxRoutes {
			return "", false
		}
	}
	origins := map[string]bool{}
	for _, re := range routes {
		oes, err := g.Edges(ctx, re.FromID, "out", "irr_origin", time.Time{})
		if err != nil {
			continue
		}
		for _, oe := range oes {
			if as, err := g.GetAsset(ctx, oe.ToID); err == nil && as.Type == "AutonomousSystem" {
				origins["AS"+graph.ContentString(as, "number")] = true
			}
		}
		if len(origins) > catalog.MaxOrigins {
			return "", false
		}
	}
	own := len(origins) > 0
	for o := range origins {
		if !ownASNumbers[o] {
			own = false
		}
	}
	if own {
		return SigIRRMaintainerOwn, true
	}
	return SigSharedIRRMaintainer, true
}

func sortedWitnessKeys(m map[string]graph.WitnessEdge) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// matchRPKIOwnASN is the matcher of the roa-authorizes-own-asn ownership
// signal.
const matchRPKIOwnASN = "rpki_own_asn"

// roaSignals finds the netblocks a valid ROA authorizes one of the subject's
// autonomous systems to announce.
func (g *gapSearch) roaSignals(as graph.Asset) error {
	def, ok := firstSignal(matchRPKIOwnASN)
	if !ok {
		return nil
	}
	steps, err := g.w.steps(as)
	if err != nil {
		return err
	}
	for _, s := range steps {
		if s.forward || s.edge.Label != "rpki_origin" || s.other.Type != "Netblock" {
			continue
		}
		witness := append(g.pathTo(as.ID), WitnessOf(s.edge, s.other, as))
		g.add(s.other, def.ID, "Netblock rpki_origin AutonomousSystem", witness)
	}
	return nil
}
