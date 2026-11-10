// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

func TestApplyOwnershipWritesOneSourcedEdgeOnSQLite(t *testing.T) {
	ctx := context.Background()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "ownership.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	cr, err := db.CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: "https://rdap.example/alumni"})
	if err != nil {
		t.Fatal(err)
	}

	o, err := db.CreateAsset(ctx, &org.Organization{ID: "synthetic-university", Name: "Synthetic University"})
	if err != nil {
		t.Fatal(err)
	}

	adapter := Adapter{Repo: db}
	proposal := ai.ProposedEdge{FromID: cr.ID, FromType: "ContactRecord", Label: "organization",
		RelationType: "SimpleRelation", ToID: o.ID, ToType: "Organization"}
	id, existed, err := adapter.ApplyOwnership(ctx, proposal, 90)
	if err != nil || existed || id == "" {
		t.Fatalf("apply = %q, %v, %v", id, existed, err)
	}

	edges, err := db.OutgoingEdges(ctx, cr, time.Time{}, "organization")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != o.ID {
		t.Fatalf("edges = %v, %v", edges, err)
	}

	evidence, err := adapter.EdgeEvidence(ctx, id, 8)
	if err != nil {
		t.Fatal(err)
	}

	found := false
	for _, ev := range evidence {
		if ev.SourceID == ai.InferenceSource {
			found = true
		}
	}
	if !found {
		t.Errorf("edge evidence %+v lacks the %s source", evidence, ai.InferenceSource)
	}

	again, existed, err := adapter.ApplyOwnership(ctx, proposal, 90)
	if err != nil || !existed || again != id {
		t.Errorf("reapply = %q, %v, %v; want the existing edge", again, existed, err)
	}

	bad := proposal
	bad.Label = "subsidiary"
	if _, _, err := adapter.ApplyOwnership(ctx, bad, 90); err == nil {
		t.Error("a relationship OAM does not define was written")
	}

	bad = proposal
	bad.FromType = "FQDN"
	if _, _, err := adapter.ApplyOwnership(ctx, bad, 90); err == nil {
		t.Error("a proposal whose entity type changed was written")
	}

	removed, err := adapter.RetractOwnership(ctx, id)
	if err != nil || !removed {
		t.Fatalf("retract = %v, %v; want the edge removed", removed, err)
	}
	if edges, err := db.OutgoingEdges(ctx, cr, time.Time{}, "organization"); err == nil && len(edges) != 0 {
		t.Errorf("edges after retract = %v", edges)
	}
}

func TestRetractOwnershipKeepsOtherSourcesOnSQLite(t *testing.T) {
	ctx := context.Background()
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "retract.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	cr, err := db.CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: "https://rdap.example/shared"})
	if err != nil {
		t.Fatal(err)
	}

	o, err := db.CreateAsset(ctx, &org.Organization{ID: "synthetic-org", Name: "Synthetic Org"})
	if err != nil {
		t.Fatal(err)
	}

	adapter := Adapter{Repo: db}
	id, _, err := adapter.ApplyOwnership(ctx, ai.ProposedEdge{FromID: cr.ID, FromType: "ContactRecord",
		Label: "organization", RelationType: "SimpleRelation", ToID: o.ID, ToType: "Organization"}, 70)
	if err != nil {
		t.Fatal(err)
	}

	edge, err := db.FindEdgeById(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.CreateEdgeProperty(ctx, edge, &general.SourceProperty{Source: "RDAP", Confidence: 100}); err != nil {
		t.Fatal(err)
	}

	removed, err := adapter.RetractOwnership(ctx, id)
	if err != nil || removed {
		t.Fatalf("retract = %v, %v; want the edge kept", removed, err)
	}

	evidence, err := adapter.EdgeEvidence(ctx, id, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, ev := range evidence {
		if ev.SourceID == ai.InferenceSource {
			t.Errorf("the %s source survived the retraction", ai.InferenceSource)
		}
	}
	if len(evidence) == 0 {
		t.Error("the RDAP source was removed")
	}
}
