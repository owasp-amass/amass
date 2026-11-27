// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"encoding/json"
	"slices"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

func (g *gapSearch) fingerprintSignals(owned graph.Asset) error {
	defs := signalsByMatcher(matchFingerprint)
	if len(defs) == 0 {
		return nil
	}

	var sources []graph.WitnessEdge
	var assets []graph.Asset
	switch owned.Type {
	case "URL":
		sources, assets = []graph.WitnessEdge{{}}, []graph.Asset{owned}
	case "FQDN", "IPAddress":
		steps, err := g.w.steps(owned)
		if err != nil {
			return err
		}
		for _, s := range steps {
			if s.forward && s.edge.Label == "port" && s.other.Type == "Service" {
				sources = append(sources, WitnessOf(s.edge, owned, s.other))
				assets = append(assets, s.other)
			}
		}
	}
	// behind a CDN or on a private address, a TLS fingerprint is the
	// provider's or the network's, not the site's
	shared, err := g.servedFromSharedInfrastructure(owned)
	if err != nil {
		return err
	}

	for i, src := range assets {
		if !g.read() {
			return nil
		}

		steps, err := g.w.steps(src)
		if err != nil {
			return err
		}
		for _, s := range steps {
			if !s.forward || s.edge.Label != "fingerprint" || s.other.Type != "Identifier" {
				continue
			}

			idType := graph.ContentString(s.other, "id_type")
			value := graph.ContentString(s.other, "id")
			for _, def := range defs {
				if !strings.EqualFold(def.Params.Property, idType) ||
					!slices.Contains(fingerprintTypes(def), src.Type) || !usefulFingerprint(def, value) ||
					(shared && def.Params.SkipSharedInfrastructure) {
					continue
				}

				lead := g.pathTo(owned.ID)
				if sources[i].Label != "" {
					lead = append(lead, sources[i])
				}
				lead = append(lead, WitnessOf(s.edge, src, s.other))
				if err := g.fingerprintMatches(def, src, s.other, lead); err != nil {
					return err
				}
			}
		}
	}

	return nil
}

// fingerprintMatches records the candidates behind the other assets that share
// the fingerprint Identifier ident with src, unless more do than the
// database's hub limit for fingerprints of its id_type (GapMaxShared
// without one).
// The shared Identifier is the pivot: its incoming "fingerprint" edges are the
// assets carrying the same value, read bounded so a value on many hosts (a
// common favicon or title) is skipped rather than walked in full. Only the
// carriers outside the footprint count toward the limit.
func (g *gapSearch) fingerprintMatches(def OwnershipSignal, src, ident graph.Asset, lead []graph.WitnessEdge) error {
	if !g.read() {
		return nil
	}

	hub := fingerprintHub(g.w.ctx, g.w.graph, graph.ContentString(ident, "id_type"), GapMaxShared, &g.hubs)
	edges, more, err := graph.ReadEdges(g.w.ctx, g.w.graph, ident.ID, "in", "fingerprint",
		g.searchBound(hub.rule.Limit, "Service", "URL"), g.read)
	if err != nil {
		return err
	}
	// the carriers outside the footprint
	var others []graph.Relation
	for _, edge := range edges {
		if _, mine := g.owned[edge.FromID]; !mine && edge.FromID != src.ID && edge.FromID != ident.ID {
			others = append(others, edge)
		}
	}
	if hub.over(graph.AssetLabel(ident), len(others), more) {
		return nil
	}

	for _, edge := range others {

		o, err := g.w.asset(edge.FromID)
		if err != nil {
			return err
		}
		if !slices.Contains(fingerprintTypes(def), o.Type) {
			continue
		}

		g.w.assets[o.ID] = o
		match := WitnessOf(edge, ident, o)
		via := src.Type + " " + def.Params.Property + " " + o.Type
		if o.Type != "Service" {
			g.add(o, def.ID, via, append(append([]graph.WitnessEdge(nil), lead...), match))
			continue
		}

		hosts, err := g.w.steps(o)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			if h.forward || h.edge.Label != "port" || (h.other.Type != "FQDN" && h.other.Type != "IPAddress") {
				continue
			}

			g.add(h.other, def.ID, via, append(append([]graph.WitnessEdge(nil), lead...), match,
				WitnessOf(h.edge, o, h.other)))
		}
	}

	return nil
}

// fingerprintTypes are the asset types a fingerprint signal reads.
func fingerprintTypes(def OwnershipSignal) []string {
	if len(def.Params.AssetTypes) > 0 {
		return def.Params.AssetTypes
	}

	return []string{"Service"}
}

// usefulFingerprint reports whether a stored value can tell owners apart:
// long enough, and not one of the signal's generic values (default pages,
// error pages, provider challenges).
func usefulFingerprint(def OwnershipSignal, value string) bool {
	v := strings.TrimSpace(value)
	if len(v) < def.Params.MinLength {
		return false
	}
	for _, ignore := range def.Params.IgnoreValues {
		if strings.EqualFold(v, strings.TrimSpace(ignore)) {
			return false
		}
	}

	return true
}

// propertyValues returns the values of an asset's stored simple properties
// named name.
func propertyValues(evidence []graph.Evidence, name string) []string {
	var out []string
	for _, e := range evidence {
		data, err := json.Marshal(e.Property)
		if err != nil {
			continue
		}

		var p struct {
			Name  string `json:"property_name"`
			Value string `json:"property_value"`
		}
		if json.Unmarshal(data, &p) == nil && strings.EqualFold(p.Name, name) && p.Value != "" &&
			!slices.Contains(out, p.Value) {
			out = append(out, p.Value)
		}
	}

	return out
}
