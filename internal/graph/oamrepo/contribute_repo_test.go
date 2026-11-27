// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// A contribution is written with its source and checked against the OAM
// schema; undoing it removes what only it recorded and keeps what a
// collector observed.
func TestContributionWriteAndUndoKeepsCollectorData(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	repo := openSQLite(t, "contribute.db")
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	apex := f.asset(&oamdns.FQDN{Name: "example.com"})
	if _, err := repo.CreateEntityProperty(ctx, apex, &oamgen.SourceProperty{Source: "DNS", Confidence: 100}); err != nil {
		t.Fatal(err)
	}

	zero := 0
	stored := &review.AssetRef{Type: "FQDN", Field: "name", Value: "example.com"}
	items := []review.ContributedItem{
		{Kind: review.ContributedAsset, AssetType: "FQDN", Fields: map[string]any{"name": "www.example.com"},
			Evidence: "the user"},
		{Kind: review.ContributedAsset, AssetType: "FQDN", Fields: map[string]any{"name": "example.com"},
			Evidence: "the user"},
		{Kind: review.ContributedRelation, From: stored, Label: "node", To: &review.AssetRef{Item: &zero},
			Evidence: "the user"},
		{Kind: review.ContributedProperty, Target: stored, Evidence: "the user",
			Fields: map[string]any{"property_name": "note", "property_value": "contributed"}},
	}
	adapter := Adapter{Repo: repo}
	source := review.ContributionSource("test")
	w, err := adapter.WriteContribution(ctx, source, items)
	if err != nil {
		t.Fatal(err)
	}
	if len(w.EntityIDs) != 2 || len(w.EdgeIDs) != 1 || len(w.Tags) != 4 {
		t.Fatalf("write = %+v", w)
	}

	out, err := repo.OutgoingEdges(ctx, apex, time.Time{}, "node")
	if err != nil || len(out) != 1 {
		t.Fatalf("node edges = %v, %v", out, err)
	}
	if got := f.edgeSources(out[0]); len(got) != 1 || got[0] != source {
		t.Fatalf("edge sources = %v", got)
	}

	if err := adapter.UndoContribution(ctx, source, w); err != nil {
		t.Fatal(err)
	}
	if got, err := repo.FindEntityById(ctx, w.EntityIDs[0]); err == nil && got != nil {
		t.Fatal("the contributed FQDN is still stored")
	}
	if _, err := repo.FindEntityById(ctx, apex.ID); err != nil {
		t.Fatalf("the collected FQDN was removed: %v", err)
	}
	if out, err := repo.OutgoingEdges(ctx, apex, time.Time{}, "node"); err == nil && len(out) > 0 {
		t.Fatal("the contributed relation is still stored")
	}
	tags, err := repo.FindEntityTags(ctx, apex, time.Time{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tag := range tags {
		names = append(names, tag.Property.Name())
	}
	if len(names) != 1 || names[0] != "DNS" {
		t.Fatalf("collected FQDN properties = %v, want only its DNS source", names)
	}
}

// An item the OAM schema does not allow is refused with the item named.
func TestContributionRefusesInvalidItems(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	adapter := Adapter{Repo: openSQLite(t, "refuse.db")}
	zero := 0

	for name, items := range map[string][]review.ContributedItem{
		"unknown field": {{Kind: review.ContributedAsset, AssetType: "FQDN",
			Fields: map[string]any{"name": "a.example.com", "color": "red"}, Evidence: "x"}},
		"unknown type": {{Kind: review.ContributedAsset, AssetType: "Spaceship",
			Fields: map[string]any{"name": "x"}, Evidence: "x"}},
		"invalid relation": {
			{Kind: review.ContributedAsset, AssetType: "FQDN", Fields: map[string]any{"name": "a.example.com"},
				Evidence: "x"},
			{Kind: review.ContributedRelation, From: &review.AssetRef{Item: &zero}, Label: "netblock",
				To: &review.AssetRef{Item: &zero}, Evidence: "x"}},
		"missing stored asset": {{Kind: review.ContributedProperty, Evidence: "x",
			Target: &review.AssetRef{Type: "FQDN", Field: "name", Value: "none.example.com"},
			Fields: map[string]any{"property_name": "n", "property_value": "v"}}},
	} {
		w, err := adapter.WriteContribution(ctx, review.ContributionSource("test"), items)
		if err == nil || !strings.Contains(err.Error(), "item ") {
			t.Errorf("%s: err = %v", name, err)
		}
		if err := adapter.UndoContribution(ctx, review.ContributionSource("test"), w); err != nil {
			t.Errorf("%s: undo: %v", name, err)
		}
	}
}
