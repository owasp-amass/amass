// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// The org-group lens lists the units the subject's own documents name: by
// the publisher placeholder or the subject's exact name, marking the ones
// already stored as its units.
func TestDocumentUnits(t *testing.T) {
	g := documentRelationFixture()
	g.EvidenceByID["f-catalog"] = append(g.EvidenceByID["f-catalog"],
		graphtest.SimpleProp(propDocStatement, `{"kind":"relation","subject":"Counseling Center",`+
			`"subject_type":"Organization","predicate":"unit_of","object":"`+DocumentPublisher+`",`+
			`"object_type":"Organization","sha256":"v2"}`))
	g.Links = append(g.Links, graph.Relation{ID: "cf", FromID: "owasp", ToID: "foundation", Label: "org_unit",
		Type: "SimpleRelation"})

	units, err := DocumentUnits(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp"], LensLimits{})
	if err != nil {
		t.Fatal(err)
	}
	byName := map[string]DocumentUnit{}
	for _, u := range units {
		byName[u.Name] = u
	}
	if u, ok := byName["OWASP Alumni Fund"]; !ok || !u.Stored || u.Documents != 2 {
		t.Errorf("foundation %+v: want stored, named by both documents", u)
	}
	if u, ok := byName["Counseling Center"]; !ok || u.Stored || u.Documents != 1 {
		t.Errorf("counseling %+v: want not stored, one document", u)
	}
	if _, ok := byName["Acme Holdings"]; ok {
		t.Error("a subsidiary_of finding was listed as a unit")
	}

	var b strings.Builder
	formatDocumentUnits(&b, units)
	if !strings.Contains(b.String(), "Units its own documents name") || !strings.Contains(b.String(),
		"Counseling Center (not stored") {
		t.Errorf("formatted %q", b.String())
	}
}

// Two organizations that are each a unit of a different parent are not one
// organization, however alike their names.
func TestDifferentParents(t *testing.T) {
	a := &orgProfile{parents: map[string]bool{"college-a": true}}
	b := &orgProfile{parents: map[string]bool{"college-b": true}}
	c := &orgProfile{parents: map[string]bool{"college-a": true}}
	if !differentParents(a, b) || differentParents(a, c) || differentParents(a, &orgProfile{}) {
		t.Error("differentParents misjudges units of different, shared or no parents")
	}
}
