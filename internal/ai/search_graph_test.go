// SPDX-License-Identifier: Apache-2.0
package ai

import (
	"context"
	"fmt"
	"testing"
)

func TestGraphSearchVariableLengthBeyondTen(t *testing.T) {
	g := fakeGraph{assets: map[string]Asset{}, links: []Relation{}}
	catalog := planCatalog{
		{SourceType: "FQDN", Label: "next", RelationType: "SimpleRelation", DestinationType: "Service"},
		{SourceType: "Service", Label: "next", RelationType: "SimpleRelation", DestinationType: "FQDN"},
	}
	for i := 0; i <= 15; i++ {
		id := fmt.Sprintf("n%02d", i)
		typ := "FQDN"
		if i%2 == 1 {
			typ = "Service"
		}
		g.assets[id] = Asset{ID: id, Type: typ, Key: id}
		if i == 0 {
			continue
		}
		prev := fmt.Sprintf("n%02d", i-1)
		eid := fmt.Sprintf("e%02d", i)
		if i%2 == 1 {
			g.links = append(g.links, Relation{ID: eid, FromID: prev, ToID: id, Label: "next", Type: "SimpleRelation"})
		} else {
			g.links = append(g.links, Relation{ID: eid, FromID: id, ToID: prev, Label: "next", Type: "SimpleRelation"})
		}
	}
	result, err := SearchGraph(context.Background(), g, catalog, DefaultLimits(), GraphSearchRequest{
		StartID: "n00", TargetTypes: []string{"Service"}, MaxDepth: 15, MaxMatches: 20,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Truncated || !result.Exhausted || len(result.Matches) != 8 {
		t.Fatalf("unexpected search result: %+v", result)
	}
	depths := map[int]bool{}
	for _, path := range result.Matches {
		depths[len(path.Edges)] = true
	}
	for _, depth := range []int{1, 3, 5, 7, 9, 11, 13, 15} {
		if !depths[depth] {
			t.Errorf("missing result at depth %d", depth)
		}
	}
}

func TestGraphSearchDiscoversIncomingPaths(t *testing.T) {
	result, err := SearchGraph(context.Background(), examplePlannedGraph(), testOAMCatalog, DefaultLimits(), GraphSearchRequest{
		StartID: "fqdn-tech", TargetTypes: []string{"Organization"}, MaxDepth: 3,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.Truncated || len(result.Matches) != 2 {
		t.Fatalf("expected two organizations at distinct depths: %+v", result)
	}
	first, last := result.Matches[0], result.Matches[1]
	if len(first.Edges) != 2 || len(last.Edges) != 3 || last.Nodes[len(last.Nodes)-1].ID != "parent" {
		t.Fatalf("unexpected paths: %+v", result.Matches)
	}
}

func TestGraphSearchDistinguishesTruncation(t *testing.T) {
	limits := DefaultLimits()
	limits.MaxPerNode = 1
	result, err := SearchGraph(context.Background(), examplePlannedGraph(), testOAMCatalog, limits, GraphSearchRequest{
		StartID: "parent", TargetTypes: []string{"FQDN"}, MaxDepth: 3,
	})
	if err != nil || !result.Truncated || result.Exhausted {
		t.Fatalf("partial query falsely complete: %+v err=%v", result, err)
	}
}

func TestGraphSearchRejectsUnknownTypes(t *testing.T) {
	_, err := SearchGraph(context.Background(), examplePlannedGraph(), testOAMCatalog, DefaultLimits(), GraphSearchRequest{
		StartID: "fqdn-tech", TargetTypes: []string{"Imaginary"},
	})
	if err == nil {
		t.Fatal("unknown OAM asset type accepted")
	}
}
