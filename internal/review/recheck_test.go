// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"fmt"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// The re-check finds evidence past the first page, and never declares
// evidence gone without reading all of it.
func TestMissingWitnessReadsPastOnePage(t *testing.T) {
	n := graph.MaxEdgeRead + 100
	last := fmt.Sprintf("h%d.owasp.org", n-1)
	w := []graph.WitnessEdge{{FromID: "owasp.org", FromType: "FQDN", From: "owasp.org", ToID: last, ToType: "FQDN",
		To: last, Label: "node"}}

	paged := graphtest.PagedVendorGraph{VendorGraph: graphtest.BusyOWASP(n), Pages: new(int)}
	if missing, err := missingWitness(context.Background(), paged, w); err != nil || missing != "" {
		t.Errorf("evidence past the first page reported missing: %q, %v", missing, err)
	}

	gone := []graph.WitnessEdge{{FromID: "owasp.org", FromType: "FQDN", From: "owasp.org", ToID: "gone.owasp.org",
		ToType: "FQDN", To: "gone.owasp.org", Label: "node"}}
	if missing, _ := missingWitness(context.Background(), paged, gone); missing == "" {
		t.Error("evidence absent from every page was not reported missing")
	}

	// Without paging the evidence cannot be confirmed either way, so it
	// counts as present.
	if missing, _ := missingWitness(context.Background(), graphtest.BusyOWASP(n), gone); missing != "" {
		t.Errorf("unread evidence was declared gone: %q", missing)
	}
}

// A matched value (two assets that share a value) is not a stored
// relationship, so the re-check never looks for it as an edge: it is gone only
// when one of its assets is.
func TestMissingWitnessMatchedValue(t *testing.T) {
	g := graphtest.BusyOWASP(3)
	shared := []graph.WitnessEdge{{FromID: "owasp.org", FromType: "FQDN", From: "owasp.org",
		ToID: "h1.owasp.org", ToType: "FQDN", To: "h1.owasp.org", Label: "same_email_domain",
		RelationType: lens.MatchedValueRelation}}
	if missing, err := missingWitness(context.Background(), g, shared); err != nil || missing != "" {
		t.Errorf("a matched value between present assets reported missing: %q, %v", missing, err)
	}

	gone := []graph.WitnessEdge{{FromID: "owasp.org", FromType: "FQDN", From: "owasp.org",
		ToID: "nowhere.owasp.org", ToType: "FQDN", To: "nowhere.owasp.org", Label: "same_email_domain",
		RelationType: lens.MatchedValueRelation}}
	if missing, _ := missingWitness(context.Background(), g, gone); missing == "" {
		t.Error("a matched value whose asset is gone was not reported missing")
	}
}
