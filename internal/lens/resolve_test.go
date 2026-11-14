// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestResolveNameFollowsAliases(t *testing.T) {
	g := graphtest.FakeGraph{Assets: map[string]graph.Asset{}}
	name := func(n string) {
		g.Assets[n] = graph.Asset{ID: n, Type: "FQDN", Key: n, Content: map[string]any{"name": n}}
	}
	record := func(from, to string, rr int) {
		g.Links = append(g.Links, graph.Relation{ID: fmt.Sprintf("%s-%d-%s", from, rr, to), FromID: from, ToID: to,
			Label: "dns_record", Type: "BasicDNSRelation", Content: map[string]any{"header": map[string]any{"rr_type": rr}}})
	}
	for _, n := range []string{"a.example", "b.example", "c.example", "loop1.example", "loop2.example"} {
		name(n)
	}
	g.Assets["ip"] = graph.Asset{ID: "ip", Type: "IPAddress", Key: "192.0.2.1", Content: map[string]any{"address": "192.0.2.1"}}
	record("a.example", "b.example", 5)
	record("b.example", "c.example", 5)
	record("c.example", "ip", 1)
	record("loop1.example", "loop2.example", 5)
	record("loop2.example", "loop1.example", 5)

	w := newLensWalker(context.Background(), g, g, graph.MeaningsOf(graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}),
		graphtest.TestOAMCatalog.Relations(), g.Assets["a.example"], &ThirdPartyReport{FootprintTypes: map[string]int{}})
	w.maxAssets, w.maxReads = LensLimits{}.assets(), LensLimits{}.reads()

	r, err := resolveName(w, g.Assets["a.example"])
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Aliases) != 2 || r.Target(g.Assets["a.example"]).ID != "c.example" || len(r.Addresses) != 1 || r.Loop {
		t.Errorf("chain = %+v", r)
	}

	r, err = resolveName(w, g.Assets["loop1.example"])
	if err != nil {
		t.Fatal(err)
	}
	if !r.Loop || len(r.Addresses) != 0 {
		t.Errorf("a looping chain = %+v", r)
	}
}
