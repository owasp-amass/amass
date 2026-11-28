// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/fingerprint"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

// fingerprintSignalFor maps a service fingerprint id_type to the horizontal
// signal it supports, for the id_types that are good horizontal evidence. A
// JARM (a TLS-stack fingerprint shared by many unrelated servers) and the page
// title (too generic) are deliberately not horizontal evidence and return
// false.
func fingerprintSignalFor(idType string) (signalID, label string, ok bool) {
	switch idType {
	case fingerprint.AnalyticsID:
		return SigSharedAnalyticsID, "shared analytics identifier", true
	case fingerprint.FaviconMMH3:
		return SigSharedFavicon, "shared favicon", true
	case fingerprint.BodySHA256:
		return SigSharedPageContent, "shared page content", true
	}

	return "", "", false
}

// sharedFingerprintPivot adds related domains whose web service carries the same
// distinctive fingerprint Identifier (analytics identifier, favicon hash or
// page-content hash) as one of the organization's own services. It walks the
// organization's controlled footprint to its services, and for each service's
// fingerprint edge to an Identifier reads the other services carrying that same
// Identifier and takes the registered domain of each one's FQDN host. A default
// or signal-free value (fingerprint_defaults.json) is skipped, and an Identifier
// carried by more distinct apex domains than the signal's hub limit
// (signals.json) is treated as a shared default or CDN value and skipped, not
// scored, and recorded.
func sharedFingerprintPivot(ctx context.Context, g graph.Graph, w *lensWalker, org graph.Asset, skips *hubSkips,
	add func(string, string, string, ...graph.WitnessEdge)) {
	owned, order, err := w.controlledFootprint([]graph.Asset{org})
	if err != nil {
		return
	}
	seenSvc := map[string]bool{}
	for _, id := range order {
		host := owned[id]
		steps, err := w.steps(host)
		if err != nil {
			continue
		}
		for _, hs := range steps {
			if !hs.forward || hs.other.Type != "Service" || seenSvc[hs.other.ID] {
				continue
			}
			seenSvc[hs.other.ID] = true
			svc := hs.other

			svcSteps, err := w.steps(svc)
			if err != nil {
				continue
			}
			for _, fs := range svcSteps {
				if !fs.forward || fs.edge.Label != "fingerprint" {
					continue
				}
				ident := fs.other
				idType := graph.ContentString(ident, "id_type")
				signalID, label, ok := fingerprintSignalFor(idType)
				if !ok {
					continue
				}
				value := graph.ContentString(ident, "id")
				if value == "" || semantics.IsDefaultFingerprint(idType, value) {
					continue
				}
				ownW := graph.WitnessEdge{EdgeID: fs.edge.ID, Label: "fingerprint", RelationType: fs.edge.Type,
					FromID: svc.ID, FromType: "Service", ToID: ident.ID, ToType: "Identifier", To: idType + ":" + value}
				fingerprintSiblings(ctx, g, svc.ID, ident.ID, signalID, label, ownW,
					signalHub(ctx, g, relatedHub(signalID), fingerprintSource(idType), "fingerprint "+idType, skips),
					add)
			}
		}
	}
}

// fingerprintSiblings reads the other carriers of the Identifier identID (web
// services, and URLs such as a domain's ads.txt) and adds the registered
// domain of each one's FQDN host, unless the Identifier is over the
// shared-value cap. ownW is the witness for the organization's own carrier
// (ownID) that holds the same Identifier.
func fingerprintSiblings(ctx context.Context, g graph.Graph, ownID, identID, signalID, label string,
	ownW graph.WitnessEdge, hub hubCheck, add func(string, string, string, ...graph.WitnessEdge)) {
	carriers, err := g.Edges(ctx, identID, "in", "fingerprint", time.Time{})
	if err != nil {
		return
	}
	type sibling struct {
		apex  string
		fpW   graph.WitnessEdge
		hostW graph.WitnessEdge
	}
	apexSet := map[string]bool{}
	var sibs []sibling
	for _, ce := range carriers {
		if ce.FromID == ownID {
			continue
		}
		for _, h := range carrierHosts(ctx, g, ce.FromID) {
			apex := graph.RegisteredDomain(graph.FQDNName(h.host))
			if apex == "" {
				continue
			}
			apexSet[apex] = true
			fpW := graph.WitnessEdge{EdgeID: ce.ID, Label: "fingerprint", RelationType: ce.Type,
				FromID: ce.FromID, FromType: h.carrierType, ToID: ce.ToID, ToType: "Identifier"}
			sibs = append(sibs, sibling{apex: apex, fpW: fpW, hostW: h.witness(apex)})
		}
	}
	if hub.exceeded(len(apexSet), false) {
		// a shared default or CDN value, not ownership evidence
		hub.record(assetName(ctx, g, identID), len(apexSet), false)
		return
	}
	for _, sb := range sibs {
		add(sb.apex, signalID, label, ownW, sb.fpW, sb.hostW)
	}

}

// carrierHost is the FQDN a fingerprint carrier belongs to, and the edge
// joining them.
type carrierHost struct {
	carrierType string
	host        graph.Asset
	edge        graph.Relation
}

// witness is the edge joining the carrier and its host, as a witness.
func (h carrierHost) witness(apex string) graph.WitnessEdge {
	if h.carrierType == "URL" {
		return graph.WitnessEdge{EdgeID: h.edge.ID, Label: h.edge.Label, RelationType: h.edge.Type,
			FromID: h.edge.FromID, FromType: "URL", ToID: h.edge.ToID, ToType: "FQDN", To: apex}
	}
	return graph.WitnessEdge{EdgeID: h.edge.ID, Label: h.edge.Label, RelationType: h.edge.Type,
		FromID: h.edge.FromID, FromType: "FQDN", ToID: h.edge.ToID, ToType: "Service", To: apex}
}

// carrierHosts returns the FQDN hosts of a fingerprint carrier: the names
// serving a Service (FQDN --port--> Service) or the host of a URL
// (URL --domain--> FQDN).
func carrierHosts(ctx context.Context, g graph.Graph, carrierID string) []carrierHost {
	var out []carrierHost
	if ports, err := g.Edges(ctx, carrierID, "in", "port", time.Time{}); err == nil {
		for _, e := range ports {
			if fq, err := g.GetAsset(ctx, e.FromID); err == nil && fq.Type == "FQDN" {
				out = append(out, carrierHost{carrierType: "Service", host: fq, edge: e})
			}
		}
	}
	if domains, err := g.Edges(ctx, carrierID, "out", "domain", time.Time{}); err == nil {
		for _, e := range domains {
			if fq, err := g.GetAsset(ctx, e.ToID); err == nil && fq.Type == "FQDN" {
				out = append(out, carrierHost{carrierType: "URL", host: fq, edge: e})
			}
		}
	}
	return out
}

// allowedOriginPivot finds the other apexes a web service on one of the
// organization's own hosts lets call or embed it (Service --allowed_origin-->
// FQDN, from CORS and CSP frame-ancestors), and adds them.
func allowedOriginPivot(ctx context.Context, g graph.Graph, ownApexes []string,
	add func(string, string, string, ...graph.WitnessEdge)) {
	for _, apexID := range ownApexes {
		hosts := []string{apexID}
		if nodes, err := g.Edges(ctx, apexID, "out", "node", time.Time{}); err == nil {
			for _, n := range nodes {
				hosts = append(hosts, n.ToID)
			}
		}
		for _, hostID := range hosts {
			ports, err := g.Edges(ctx, hostID, "out", "port", time.Time{})
			if err != nil {
				continue
			}
			for _, pe := range ports {
				origins, err := g.Edges(ctx, pe.ToID, "out", "allowed_origin", time.Time{})
				if err != nil {
					continue
				}
				for _, oe := range origins {
					o, err := g.GetAsset(ctx, oe.ToID)
					if err != nil {
						continue
					}
					apex := graph.RegisteredDomain(graph.FQDNName(o))
					if apex == "" {
						continue
					}
					portW := graph.WitnessEdge{EdgeID: pe.ID, Label: "port", RelationType: pe.Type,
						FromID: pe.FromID, FromType: "FQDN", ToID: pe.ToID, ToType: "Service"}
					originW := graph.WitnessEdge{EdgeID: oe.ID, Label: "allowed_origin", RelationType: oe.Type,
						FromID: oe.FromID, FromType: "Service", ToID: oe.ToID, ToType: "FQDN"}
					add(apex, SigAllowedOrigin, "allowed origin", portW, originW)
				}
			}
		}
	}
}
