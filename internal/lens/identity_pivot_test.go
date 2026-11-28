// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// identityGraph puts acme.net (an apex of the organization) on an identity
// tenant shared with acme-ops.org and acme.com (its own), lists
// acme-brand.org as a federated sibling, and has acme.net sign in at its own
// federation server, whose signing certificate the federation server of
// acme-partner.org also uses, where acme-shop.org signs in. holders more
// apexes share the tenant.
func identityGraph(holders int) graphtest.FakeGraph {
	g := relatedDomainsGraph()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	fqdn := func(id, name string) { add(id, "FQDN", name, map[string]any{"name": name}) }
	link := func(from, to, label string) {
		g.Links = append(g.Links, graph.Relation{ID: label + from + to, FromID: from, ToID: to, Label: label,
			Type: "SimpleRelation"})
	}

	add("tenant", "Identifier", "azure_tenant_id:0a1b2c3d", map[string]any{"unique_id": "azure_tenant_id:0a1b2c3d",
		"id": "0a1b2c3d", "id_type": "azure_tenant_id"})
	fqdn("fq_acme_ops", "acme-ops.org")
	fqdn("fq_acme_com", "acme.com")
	link("fq_acme_net", "tenant", "identity_tenant")
	link("fq_acme_ops", "tenant", "identity_tenant")
	link("fq_acme_com", "tenant", "identity_tenant")
	for i := 0; i < holders; i++ {
		id := fmt.Sprintf("fq_msp%d", i)
		fqdn(id, fmt.Sprintf("client%d.example", i))
		link(id, "tenant", "identity_tenant")
	}

	fqdn("fq_acme_brand", "acme-brand.org")
	link("fq_acme_net", "fq_acme_brand", "federated_with")

	fqdn("sts_own", "sts.acme.net")
	fqdn("sts_partner", "sts.acme-partner.org")
	fqdn("fq_acme_shop", "acme-shop.org")
	add("signer", "TLSCertificate", "signer", map[string]any{"subject_common_name": "ADFS Signing"})
	link("fq_acme_net", "sts_own", "identity_provider")
	link("sts_own", "signer", "signing_certificate")
	link("sts_partner", "signer", "signing_certificate")
	link("fq_acme_shop", "sts_partner", "identity_provider")
	return g
}

// identitySignals returns the signals of each related domain.
func identitySignals(t *testing.T, g graphtest.FakeGraph) map[string][]string {
	t.Helper()
	r, err := FindRelatedDomains(context.Background(), g, nil, "acme")
	if err != nil {
		t.Fatal(err)
	}
	out := map[string][]string{}
	for _, d := range r.Domains {
		out[d.Domain] = d.SignalIDs
	}
	return out
}

func TestIdentityPivot(t *testing.T) {
	got := identitySignals(t, identityGraph(0))
	for domain, want := range map[string]string{
		"acme-ops.org":     SigSharedIdentityTenant,
		"acme-brand.org":   SigFederatedSibling,
		"acme-partner.org": SigSharedSigningCert,
		"acme-shop.org":    SigSharedSigningCert,
	} {
		if !slices.Contains(got[domain], want) {
			t.Errorf("%s: signals %v lack %s", domain, got[domain], want)
		}
	}
	if slices.Contains(got["acme.com"], SigSharedIdentityTenant) {
		t.Error("the organization's own domain was a tenant candidate")
	}

	// a tenant on more registered domains than the hub limit is a provider's
	limit := relatedHub(SigSharedIdentityTenant).Limit
	got = identitySignals(t, identityGraph(limit))
	if slices.Contains(got["acme-ops.org"], SigSharedIdentityTenant) {
		t.Errorf("a tenant shared by %d more domains still counted", limit)
	}
	if !slices.Contains(got["acme-brand.org"], SigFederatedSibling) {
		t.Error("the tenant's hub limit stopped the federated sibling")
	}
}
