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

func TestFindCorporateGroup(t *testing.T) {
	g := graphtest.GroupFixture()
	r, err := FindCorporateGroup(context.Background(), g, g.Assets["usa"])
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Tops) != 1 || r.Tops[0].ID != "sa" || r.Truncated {
		t.Fatalf("tops = %+v, truncated %v (%s)", r.Tops, r.Truncated, r.Reason)
	}
	if strings.Join(r.Labels, ",") != "org_unit,subsidiary" {
		t.Errorf("labels from the semantics table = %v", r.Labels)
	}

	depth := map[string]int{}
	for _, m := range r.Members {
		depth[m.Organization.ID] = m.Depth
	}
	want := map[string]int{"sa": 0, "ab": 1, "usa": 2, "uk": 2, "sec": 2}
	if len(depth) != len(want) {
		t.Errorf("members = %v, want %v", depth, want)
	}
	for id, d := range want {
		if got, ok := depth[id]; !ok || got != d {
			t.Errorf("%s at depth %d (present %v), want %d", id, got, ok, d)
		}
	}

	text := FormatGroupReport(r)
	for _, want := range []string{"Ultimate parent: Utica Products Holdings S.A.",
		"  subsidiary: Utica Products AB [SE 5560000001]", "    subsidiary: Utica Products USA Inc. [US-DE 1000001] <- asked about",
		"    org_unit: Utica Products Security"} {
		if !strings.Contains(text, want) {
			t.Errorf("report lacks %q:\n%s", want, text)
		}
	}
	if strings.Contains(text, "Fans Club") {
		t.Errorf("an unrelated company joined the group:\n%s", text)
	}
}

func TestCorporateGroupEdgeCases(t *testing.T) {
	// Two sources name different parents.
	g := graphtest.GroupFixture()
	g.Assets["lux"] = graph.Asset{ID: "lux", Type: "Organization", Key: "Other Parent", Content: map[string]any{
		"name": "Other Parent"}}
	g.Links = append(g.Links, graph.Relation{ID: "lux-sub-ab", FromID: "lux", ToID: "ab", Label: "subsidiary",
		Type: "SimpleRelation"})
	r, err := FindCorporateGroup(context.Background(), g, g.Assets["usa"])
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Tops) != 2 || !strings.Contains(FormatGroupReport(r), "Sources disagree on the ultimate parent") {
		t.Errorf("conflicting parents: tops %+v\n%s", r.Tops, FormatGroupReport(r))
	}

	// A cycle ends, and says so.
	c := graphtest.GroupFixture()
	c.Links = append(c.Links, graph.Relation{ID: "usa-sub-sa", FromID: "usa", ToID: "sa", Label: "subsidiary",
		Type: "SimpleRelation"})
	r, err = FindCorporateGroup(context.Background(), c, c.Assets["usa"])
	if err != nil {
		t.Fatal(err)
	}
	if !r.Truncated || !strings.Contains(r.Reason, "cycle: ") || !strings.Contains(r.Reason, "which is below it") ||
		len(r.Members) == 0 {
		t.Errorf("cycle: %+v", r)
	}

	// An organization with no stored corporate links.
	r, err = FindCorporateGroup(context.Background(), g, g.Assets["other"])
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Members) != 1 || !strings.Contains(FormatGroupReport(r), "No parent, subsidiary or unit") {
		t.Errorf("lone organization:\n%s", FormatGroupReport(r))
	}
}

// From a domain, the group is its main organization's.
func TestCorporateGroupFromDomain(t *testing.T) {
	g := graphtest.FamilyGraph()
	g.Assets["holding"] = graph.Asset{ID: "holding", Type: "Organization", Key: "utica health system",
		Content: map[string]any{"name": "utica health system"}}
	g.Links = append(g.Links, graph.Relation{ID: "holding-sub-uu-arin", FromID: "holding", ToID: "uu-arin",
		Label: "subsidiary", Type: "SimpleRelation"})

	r, err := FindCorporateGroup(context.Background(), g, g.Assets["utica.edu"])
	if err != nil {
		t.Fatal(err)
	}
	if r.Domain != "utica.edu" || r.Subject.ID != "uu-arin" || len(r.Tops) != 1 || r.Tops[0].ID != "holding" {
		t.Errorf("domain %q subject %s tops %+v", r.Domain, r.Subject.ID, r.Tops)
	}
}
