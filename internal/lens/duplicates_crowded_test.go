// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"fmt"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// An address a registered agent shares with many companies says nothing
// about two of them, while a company's own office still does.
func TestCrowdedAddressesAreNotShared(t *testing.T) {
	g := graphtest.NewOrgGraph()

	g.Org("a1", "northwind traders", "", "US-DE", "")
	g.Org("a2", "northwind traders", "northwind traders llc", "US-DE", "")
	g.Contact("a1", "cr-a1", "agent")
	g.Contact("a2", "cr-a2", "agent")
	for i := 0; i <= PivotSharedAddressOrgs; i++ {
		id := fmt.Sprintf("tenant%d", i)
		g.Org(id, fmt.Sprintf("tenant company %d", i), "", "US-DE", "")
		g.Link(id, "agent", "legal_address")
	}

	g.Org("b1", "contoso labs", "", "US-NY", "")
	g.Org("b2", "contoso labs", "contoso labs inc", "US-NY", "")
	g.Contact("b1", "cr-b1", "office")
	g.Contact("b2", "cr-b2", "office")

	r, err := FindDuplicateOrganizations(context.Background(), g.Graph)
	if err != nil {
		t.Fatal(err)
	}

	if got := findPair(r, "a1", "a2"); got == nil {
		t.Fatal("the same-named companies are not compared at all")
	} else if slices.Contains(dupSignalIDs(got), "shared_location") {
		t.Errorf("a registered agent's address linked two companies: %v", dupSignalIDs(got))
	}
	if got := findPair(r, "b1", "b2"); got == nil || !slices.Contains(dupSignalIDs(got), "shared_location") {
		t.Errorf("a company's own office no longer links its two records: %+v", got)
	}
}

// Two records of one company with the same SAM.gov Unique Entity ID are
// one company.
func TestSharedUEIIsARegistryIdentifier(t *testing.T) {
	g := graphtest.NewOrgGraph()
	g.Org("u1", "fabrikam research", "", "US-NY", "")
	g.Org("u2", "fabrikam research", "fabrikam research corp", "US-NY", "")
	g.Ident("u1", "UEI", "ABC123DEF456")
	g.Ident("u2", "UEI", "ABC123DEF456")

	r, err := FindDuplicateOrganizations(context.Background(), g.Graph)
	if err != nil {
		t.Fatal(err)
	}
	if got := findPair(r, "u1", "u2"); got == nil || !slices.Contains(dupSignalIDs(got), "shared_registry_identifier") {
		t.Errorf("a shared UEI did not link the records: %+v", got)
	}
}
