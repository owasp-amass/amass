// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

func TestTableColumnsAreValidated(t *testing.T) {
	types := graph.CatalogTypes(graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}.Relations(), nil)
	for _, tc := range []struct {
		cols []TableColumn
		ok   bool
	}{
		{[]TableColumn{{Type: "IPAddress"}, {Type: "Organization", Role: ColumnController}}, true},
		{nil, false},
		{[]TableColumn{{Type: "Website"}}, false},
		{[]TableColumn{{Type: "IPAddress", Role: ColumnController}}, false},
		{[]TableColumn{{Type: "IPAddress", Role: "owner"}}, false},
		{[]TableColumn{{Type: "Organization", Role: ColumnController}, {Type: "Organization", Role: ColumnController}},
			false},
		{[]TableColumn{{Type: "IPAddress"}, {Type: "IPAddress"}}, false},
		{[]TableColumn{{Type: "Organization", Role: ColumnController}}, true},
	} {
		if err := ValidateColumns(tc.cols, types); (err == nil) != tc.ok {
			t.Errorf("columns %+v: err=%v, want ok=%v", tc.cols, err, tc.ok)
		}
	}
}

func TestRepairColumnsReadsMisplacedControllersAsTypes(t *testing.T) {
	got := RepairColumns([]TableColumn{{Type: "Service", Role: ColumnController},
		{Type: "Organization", Role: ColumnController}, {Type: "Organization", Role: ColumnController}})
	want := []TableColumn{{Type: "Service"}, {Type: "Organization", Role: ColumnController}}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("repaired = %+v, want %+v", got, want)
	}
}

func TestReservedName(t *testing.T) {
	for name, want := range map[string]bool{"msv1.invalid": true, "host.test.": true, "localhost": true,
		"www.example": true, "example.com": false, "invalidate.net": false} {
		if got := reservedName(name); got != want {
			t.Errorf("reservedName(%q) = %v, want %v", name, got, want)
		}
	}
}
