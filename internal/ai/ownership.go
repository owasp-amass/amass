// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"fmt"
	"sort"
	"strings"
)

// Attribution values, matching internal/ai/semantics.
const (
	attrController  = "controller"
	attrControls    = "controls"
	attrSameSubject = "same_subject"
	attrThirdParty  = "third_party"
)

// AttributionCatalog is implemented by schema catalogs that know what each
// OAM relationship says about who controls an asset (see
// internal/ai/semantics/oam_relations.yaml).
type AttributionCatalog interface {
	Attribution(source, label, relationType, destination string) (string, bool)
}

// ThirdPartyConnection is an Organization reached from the investigated
// asset only through a relationship that names a separate provider, issuer,
// registrar or operator. It is reported, but never as the asset's owner.
type ThirdPartyConnection struct {
	AssetID     string `json:"asset_id"`
	Display     string `json:"display"`
	Via         string `json:"via"`
	Attribution string `json:"attribution"`
	PathID      string `json:"path_id"`
}

// stepAttribution classifies traversal step i of path p (from p.Nodes[i]
// to p.Nodes[i+1]) for ownership. It returns whether owner attribution
// passes through the step, and the attribution of the stored edge.
//
// Attribution passes when the step moves toward the party that controls
// the starting asset:
//   - same_subject edges, in either direction;
//   - controller edges followed forward (to the party that controls the
//     source, such as a domain registrant);
//   - controls edges followed backward (from an asset to the party that
//     controls it, such as from a URL to the Organization with that website).
func stepAttribution(cat AttributionCatalog, p PlanMatch, i int) (bool, string) {
	e := p.Edges[i]
	from, to := p.Nodes[i], p.Nodes[i+1]
	forward := e.FromID == from.ID && e.ToID == to.ID
	src, dst := from.Type, to.Type
	if !forward {
		src, dst = to.Type, from.Type
	}
	attr, ok := cat.Attribution(src, e.Label, e.Type, dst)
	if !ok {
		return false, ""
	}
	switch attr {
	case attrSameSubject:
		return true, attr
	case attrController:
		return forward, attr
	case attrControls:
		return !forward, attr
	}
	return false, attr
}

// ownerAttributed reports whether every step from the root to the first
// Organization on p passes owner attribution. It also returns the first
// step that does not, for third-party reporting.
func ownerAttributed(cat AttributionCatalog, p PlanMatch) (bool, int, string) {
	for i := 0; i+1 < len(p.Nodes) && i < len(p.Edges); i++ {
		pass, attr := stepAttribution(cat, p, i)
		if !pass {
			return false, i, attr
		}
		if p.Nodes[i+1].Type == "Organization" {
			return true, -1, ""
		}
	}
	return false, -1, ""
}

// thirdPartyConnections lists Organizations that paths reach as a third
// party: the last step on the path that does not pass owner attribution is
// a third_party relationship, and every step after it passes (for example
// the issuer contact's organization). How the path reached that point does
// not matter: the authority that issued a certificate covering the asset is
// a third party of the asset, even when the certificate was found through a
// shared SAN. One entry per Organization, preferring the shortest path.
func thirdPartyConnections(cat AttributionCatalog, paths []PlanMatch) []ThirdPartyConnection {
	best := map[string]ThirdPartyConnection{}
	depth := map[string]int{}
	for _, p := range paths {
		if len(p.Nodes) < 2 || len(p.Edges) != len(p.Nodes)-1 || p.Nodes[len(p.Nodes)-1].Type != "Organization" {
			continue
		}
		last, lastAttr := -1, ""
		for i := range p.Edges {
			if pass, attr := stepAttribution(cat, p, i); !pass {
				last, lastAttr = i, attr
			}
		}
		if last < 0 || lastAttr != attrThirdParty {
			continue
		}
		org := p.Nodes[len(p.Nodes)-1]
		if d, seen := depth[org.ID]; seen && d <= len(p.Edges) {
			continue
		}
		id := p.PathID
		if id == "" {
			id = WitnessPathID(p)
		}
		depth[org.ID] = len(p.Edges)
		best[org.ID] = ThirdPartyConnection{AssetID: org.ID, Display: humanAsset(org),
			Via: p.Nodes[last].Type + " " + p.Edges[last].Label, Attribution: attrThirdParty, PathID: id}
	}
	out := make([]ThirdPartyConnection, 0, len(best))
	for _, c := range best {
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Display < out[j].Display })
	return out
}

// thirdPartySummary renders third-party connections for an answer.
func thirdPartySummary(conns []ThirdPartyConnection) string {
	if len(conns) == 0 {
		return ""
	}
	parts := make([]string, 0, len(conns))
	for _, c := range conns {
		parts = append(parts, fmt.Sprintf("%s via %s", c.Display, c.Via))
	}
	return " Organizations connected only as third parties (providers, issuers or registrars, not owners): " +
		strings.Join(parts, "; ") + "."
}
