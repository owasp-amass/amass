// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

func TestWidelySharedValuesGiveNoIdentitySignal(t *testing.T) {
	g := aitest.CampusGapsFixture()
	for i := 0; i <= GapMaxShared; i++ {
		id := fmt.Sprintf("cr-tenant-%d", i)
		g.Assets[id] = graph.Asset{ID: id, Type: "ContactRecord", Key: "https://rdap.example/" + id}
		for _, v := range []string{"phone", "loc"} {
			g.Links = append(g.Links, graph.Relation{ID: id + "-" + v, FromID: id, ToID: v,
				Label: map[string]string{"phone": "phone", "loc": "location"}[v], Type: "SimpleRelation"})
		}
	}

	r, err := SearchOwnershipGaps(context.Background(), g, aitest.VendorCatalog{PlanCatalog: aitest.TestOAMCatalog}, g.Assets["colgate"])
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
