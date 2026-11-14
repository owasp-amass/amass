// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"fmt"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/ai/aitest"
	"github.com/owasp-amass/amass/v5/internal/ai/graph"
)

// The re-check finds evidence past the first page, and never declares
// evidence gone without reading all of it.
func TestMissingWitnessReadsPastOnePage(t *testing.T) {
	n := graph.MaxEdgeRead + 100
	last := fmt.Sprintf("h%d.colgate.edu", n-1)
	w := []graph.WitnessEdge{{FromID: "colgate.edu", FromType: "FQDN", From: "colgate.edu", ToID: last, ToType: "FQDN",
		To: last, Label: "node"}}

	paged := aitest.PagedVendorGraph{VendorGraph: aitest.BusyColgate(n), Pages: new(int)}
	if missing, err := missingWitness(context.Background(), paged, w); err != nil || missing != "" {
		t.Errorf("evidence past the first page reported missing: %q, %v", missing, err)
	}

	gone := []graph.WitnessEdge{{FromID: "colgate.edu", FromType: "FQDN", From: "colgate.edu", ToID: "gone.colgate.edu",
		ToType: "FQDN", To: "gone.colgate.edu", Label: "node"}}
	if missing, _ := missingWitness(context.Background(), paged, gone); missing == "" {
		t.Error("evidence absent from every page was not reported missing")
	}

	// Without paging the evidence cannot be confirmed either way, so it
	// counts as present.
	if missing, _ := missingWitness(context.Background(), aitest.BusyColgate(n), gone); missing != "" {
		t.Errorf("unread evidence was declared gone: %q", missing)
	}
}
