// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestWidelySharedValuesGiveNoIdentitySignal(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	for i := 0; i <= GapMaxShared; i++ {
		id := fmt.Sprintf("cr-tenant-%d", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "ContactRecord", Key: "https://rdap.example/" + id}
		for _, v := range []string{"phone", "loc"} {
			g.Links = append(g.Links, graph.Relation{ID: id + "-" + v, FromID: id, ToID: v,
				Label: map[string]string{"phone": "phone", "loc": "street_address"}[v], Type: "SimpleRelation"})
		}
	}

	r, err := SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp"])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Candidates {
		for _, s := range c.Signals {
			if s.Kind == SignalIdentity {
				t.Fatalf("a value shared by %d assets gave an identity signal to %s", GapMaxShared+1, c.Asset)
			}
		}
	}
}

// The organization's own contact records sharing a value never make it a
// hub: only holders outside the footprint count toward the limit.
func TestOwnHoldersDoNotMakeAHub(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	for i := 0; i <= GapMaxShared; i++ {
		id := fmt.Sprintf("cr-own-%d", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "ContactRecord", Key: "https://rdap.example/" + id}
		g.Links = append(g.Links,
			graph.Relation{ID: id + "-org", FromID: id, ToID: "owasp", Label: "organization", Type: "SimpleRelation"},
			graph.Relation{ID: id + "-phone", FromID: id, ToID: "phone", Label: "phone", Type: "SimpleRelation"})
	}

	r, err := SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp"])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Candidates {
		if c.AssetID != "cr-alt" {
			continue
		}
		for _, s := range c.Signals {
			if s.Signal == sigSharedRegistrant && strings.Contains(s.Via, "phone") {
				return
			}
		}
		t.Fatalf("cr-alt's signals = %+v, want the shared phone", c.Signals)
	}
	t.Fatalf("cr-alt is not a candidate; hub skips %+v", r.HubSkips)
}

// A service's fingerprints are not registrant details: a JARM shared with an
// unrelated service gives no shared-registrant signal (the fingerprint
// signals judge it, as a weak tiebreaker).
func TestFingerprintsAreNotRegistrantDetails(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	add := func(id, typ, key string, content map[string]any) {
		g.Assets[id] = graph.Asset{ID: id, Type: typ, Key: key, Content: content}
	}
	link := func(from, label, to, rt string) {
		g.Links = append(g.Links, graph.Relation{ID: from + "-" + label + "-" + to, FromID: from, ToID: to, Label: label,
			Type: rt})
	}
	add("jarm", "Identifier", "JARM:27d27d27d00027d00041d41d00041da7", map[string]any{"id": "27d27d27d00027d00041d41d00041da7",
		"id_type": "JARM"})
	add("svc-own", "Service", "www.owasp.org:443", map[string]any{"unique_id": "www.owasp.org:443"})
	link("www.owasp.org", "port", "svc-own", "PortRelation")
	link("svc-own", "fingerprint", "jarm", "SimpleRelation")
	add("other.example", "FQDN", "other.example", map[string]any{"name": "other.example"})
	add("svc-other", "Service", "other.example:443", map[string]any{"unique_id": "other.example:443"})
	link("other.example", "port", "svc-other", "PortRelation")
	link("svc-other", "fingerprint", "jarm", "SimpleRelation")

	r, err := SearchOwnershipGaps(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp"])
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range r.Candidates {
		for _, s := range c.Signals {
			if s.Signal == sigSharedRegistrant && strings.Contains(s.Via, "fingerprint") {
				t.Fatalf("%s %s got shared registrant details from a fingerprint: %+v", c.Type, c.Asset, s)
			}
		}
	}
}
