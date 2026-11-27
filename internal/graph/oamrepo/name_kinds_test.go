// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
)

// Deciding a kept name writes the Person or Organization linked from its
// record and drops the kept name; retracting puts the name back and removes
// what the decision created.
func TestApplyRetractNameKind(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "namekinds.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx := context.Background()
	a := Adapter{Repo: repo}
	rec, err := repo.CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: "https://rdap.example/entity/1"})
	if err != nil {
		t.Fatal(err)
	}
	kept := func() []string {
		t.Helper()
		tags, _ := repo.FindEntityTags(ctx, rec, time.Time{}, graph.UncertainNameProp)
		var names []string
		for _, tag := range tags {
			names = append(names, tag.Property.Value())
		}
		return names
	}
	outgoing := func(label string) int {
		t.Helper()
		edges, _ := repo.OutgoingEdges(ctx, rec, time.Time{}, label)
		return len(edges)
	}

	for _, tc := range []struct {
		name, kind, label string
	}{
		{"Pat Lee", review.NameKindPerson, "person"},
		{"Acme Widgets", review.NameKindOrganization, "organization"},
	} {
		if _, err := repo.CreateEntityProperty(ctx, rec,
			&oamgen.SimpleProperty{PropertyName: graph.UncertainNameProp, PropertyValue: tc.name}); err != nil {
			t.Fatal(err)
		}
		p := review.NameKindProposal{ID: review.NameKindProposalID(rec.ID, "person", tc.name), RecordID: rec.ID,
			RecordType: "ContactRecord", Label: "person", Name: tc.name}

		o, err := a.ApplyNameKind(ctx, p, tc.kind, 100)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if !o.Created || o.EntityID == "" || o.EdgeID == "" {
			t.Fatalf("%s: outcome %+v", tc.name, o)
		}
		if n := outgoing(tc.label); n != 1 {
			t.Fatalf("%s: %d %s relationship(s), want 1", tc.name, n, tc.label)
		}
		if names := kept(); len(names) != 0 {
			t.Fatalf("%s: names still kept after the decision: %v", tc.name, names)
		}

		if err := a.RetractNameKind(ctx, p, o); err != nil {
			t.Fatalf("%s: retract: %v", tc.name, err)
		}
		if n := outgoing(tc.label); n != 0 {
			t.Fatalf("%s: %d %s relationship(s) after retracting, want 0", tc.name, n, tc.label)
		}
		if ent, err := repo.FindEntityById(ctx, o.EntityID); err == nil && ent != nil {
			t.Fatalf("%s: the %s the decision created is still stored", tc.name, tc.kind)
		}
		if names := kept(); len(names) != 1 || names[0] != tc.name {
			t.Fatalf("%s: kept names after retracting %v", tc.name, names)
		}
		// Clear the name for the next case.
		tags, _ := repo.FindEntityTags(ctx, rec, time.Time{}, graph.UncertainNameProp)
		for _, tag := range tags {
			_ = repo.DeleteEntityTag(ctx, tag.ID)
		}
	}
}
