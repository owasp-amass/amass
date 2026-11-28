// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
)

// identityPivot ties other registered domains to the organization through
// its identity system (engine/plugins/identity):
//   - another domain whose identity_tenant is the same Identifier (an Entra
//     tenant GUID or an Okta organization) as one of the organization's
//     domains (SigSharedIdentityTenant);
//   - a domain Microsoft lists as sharing one of its domains' tenant
//     (federated_with, SigFederatedSibling);
//   - a domain signing in at a federation server whose token-signing
//     certificate is also one of the organization's own federation servers'
//     (SigSharedSigningCert).
func identityPivot(ctx context.Context, g graph.Graph, ownApexes, ownDomains []string, skips *hubSkips,
	add func(string, string, string, ...graph.WitnessEdge)) {
	tenantHub := signalHub(ctx, g, relatedHub(SigSharedIdentityTenant), edgeSource("identity_tenant", "in"),
		"identity tenant", skips)
	certHub := signalHub(ctx, g, relatedHub(SigSharedSigningCert), graph.HubSource{}, "signing certificate", skips)

	seen := map[string]bool{}
	for _, apexID := range ownApexes {
		edges, _ := g.Edges(ctx, apexID, "out", "identity_tenant", time.Time{})
		for _, te := range edges {
			if !seen[te.ToID] {
				seen[te.ToID] = true
				sharedTenant(ctx, g, te, ownDomains, tenantHub, add)
			}
		}

		sibs, _ := g.Edges(ctx, apexID, "out", "federated_with", time.Time{})
		for _, se := range sibs {
			if apex := apexOf(ctx, g, se.ToID); apex != "" && !withinAny(apex, ownDomains) {
				add(apex, SigFederatedSibling, "listed by Microsoft as sharing the organization's tenant",
					witnessOf(se, "FQDN", "FQDN"))
			}
		}

		idps, _ := g.Edges(ctx, apexID, "out", "identity_provider", time.Time{})
		for _, ie := range idps {
			if withinAny(hostOf(ctx, g, ie.ToID), ownDomains) {
				sharedSigningCerts(ctx, g, ie, ownDomains, certHub, add)
			}
		}
	}
}

// sharedTenant adds the other registered domains whose identity tenant is
// the one te reaches, unless more domains than the hub limit share it (a
// provider's or managed service's tenant).
func sharedTenant(ctx context.Context, g graph.Graph, te graph.Relation, ownDomains []string, hub hubCheck,
	add func(string, string, string, ...graph.WitnessEdge)) {
	holders, err := g.Edges(ctx, te.ToID, "in", "identity_tenant", time.Time{})
	if err != nil {
		return
	}
	apexes := map[string]graph.Relation{}
	for _, he := range holders {
		if apex := apexOf(ctx, g, he.FromID); apex != "" {
			apexes[apex] = he
		}
	}
	tenant := assetName(ctx, g, te.ToID)
	if hub.over(tenant, len(apexes), false) {
		return
	}
	ownW := witnessOf(te, "FQDN", "Identifier")
	for _, apex := range sortedRelationKeys(apexes) {
		if !withinAny(apex, ownDomains) {
			add(apex, SigSharedIdentityTenant, "same identity tenant "+tenant, ownW,
				witnessOf(apexes[apex], "FQDN", "Identifier"))
		}
	}
}

// sharedSigningCerts adds the registered domains of the other federation
// servers that sign with one of the certificates of the organization's own
// federation server ie reaches, and of the domains signing in at them.
func sharedSigningCerts(ctx context.Context, g graph.Graph, ie graph.Relation, ownDomains []string, hub hubCheck,
	add func(string, string, string, ...graph.WitnessEdge)) {
	certs, _ := g.Edges(ctx, ie.ToID, "out", "signing_certificate", time.Time{})
	for _, ce := range certs {
		servers, err := g.Edges(ctx, ce.ToID, "in", "signing_certificate", time.Time{})
		if err != nil || hub.over(assetName(ctx, g, ce.ToID), len(servers), false) {
			continue
		}
		ownW := []graph.WitnessEdge{witnessOf(ie, "FQDN", "FQDN"), witnessOf(ce, "FQDN", "TLSCertificate")}
		for _, se := range servers {
			if se.FromID == ie.ToID {
				continue
			}
			serverW := witnessOf(se, "FQDN", "TLSCertificate")
			label := "same federation signing certificate as " + hostOf(ctx, g, ie.ToID)
			if apex := apexOf(ctx, g, se.FromID); apex != "" && !withinAny(apex, ownDomains) {
				add(apex, SigSharedSigningCert, label, append(ownW, serverW)...)
			}
			users, _ := g.Edges(ctx, se.FromID, "in", "identity_provider", time.Time{})
			for _, ue := range users {
				if apex := apexOf(ctx, g, ue.FromID); apex != "" && !withinAny(apex, ownDomains) {
					add(apex, SigSharedSigningCert, label, append(ownW, serverW, witnessOf(ue, "FQDN", "FQDN"))...)
				}
			}
		}
	}
}

// hostOf is the name of the FQDN with id, or "".
func hostOf(ctx context.Context, g graph.Graph, id string) string {
	a, err := g.GetAsset(ctx, id)
	if err != nil {
		return ""
	}
	return graph.FQDNName(a)
}

// apexOf is the registered domain of the FQDN with id, or "".
func apexOf(ctx context.Context, g graph.Graph, id string) string {
	return graph.RegisteredDomain(hostOf(ctx, g, id))
}
