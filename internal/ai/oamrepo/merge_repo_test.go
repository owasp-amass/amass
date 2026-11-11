// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestMergeAndUnmergeOrganizationsOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "merge.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	mergeAndUnmerge(t, repo)
}

// TestMergeAndUnmergeOrganizationsOnPostgres runs the same merge against
// the empty PostgreSQL database named by AMASS_AI_POSTGRES_MERGE_DSN.
func TestMergeAndUnmergeOrganizationsOnPostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_POSTGRES_MERGE_DSN")
	if dsn == "" {
		t.Skip("AMASS_AI_POSTGRES_MERGE_DSN is not set")
	}

	repo, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	mergeAndUnmerge(t, repo)
}

type mergeFixture struct {
	t    *testing.T
	ctx  context.Context
	repo repository.Repository
}

func (f mergeFixture) asset(a oam.Asset) *dbt.Entity {
	f.t.Helper()
	e, err := f.repo.CreateAsset(f.ctx, a)
	if err != nil {
		f.t.Fatal(err)
	}
	return e
}

func (f mergeFixture) edge(from, to *dbt.Entity, label, src string) *dbt.Edge {
	f.t.Helper()
	e, err := f.repo.CreateEdge(f.ctx, &dbt.Edge{FromEntity: from, ToEntity: to,
		Relation: &oamgen.SimpleRelation{Name: label}})
	if err != nil {
		f.t.Fatal(err)
	}
	if src != "" {
		if _, err := f.repo.CreateEdgeProperty(f.ctx, e, &oamgen.SourceProperty{Source: src, Confidence: 100}); err != nil {
			f.t.Fatal(err)
		}
	}
	return e
}

// links returns "direction label other-id" for each of id's edges.
func (f mergeFixture) links(id string) map[string]*dbt.Edge {
	f.t.Helper()
	ent, err := f.repo.FindEntityById(f.ctx, id)
	if err != nil {
		f.t.Fatal(err)
	}

	out := map[string]*dbt.Edge{}
	for _, dir := range []string{"out", "in"} {
		var edges []*dbt.Edge
		if dir == "out" {
			edges, err = f.repo.OutgoingEdges(f.ctx, ent, time.Time{})
		} else {
			edges, err = f.repo.IncomingEdges(f.ctx, ent, time.Time{})
		}
		if err != nil && !emptyEdgeLookup(err) {
			f.t.Fatal(err)
		}
		for _, e := range edges {
			other := e.ToEntity.ID
			if dir == "in" {
				other = e.FromEntity.ID
			}
			out[dir+" "+e.Relation.Label()+" "+other] = e
		}
	}
	return out
}

func (f mergeFixture) edgeSources(e *dbt.Edge) []string {
	f.t.Helper()
	tags, err := f.repo.FindEdgeTags(f.ctx, e, time.Time{})
	if err != nil && !emptyTagLookup(err) {
		f.t.Fatal(err)
	}
	var out []string
	for _, t := range tags {
		out = append(out, source(t.Property))
	}
	return out
}

func (f mergeFixture) entitySources(id string) []string {
	f.t.Helper()
	ent, err := f.repo.FindEntityById(f.ctx, id)
	if err != nil {
		f.t.Fatal(err)
	}
	tags, err := f.repo.FindEntityTags(f.ctx, ent, time.Time{})
	if err != nil && !emptyTagLookup(err) {
		f.t.Fatal(err)
	}
	var out []string
	for _, t := range tags {
		out = append(out, source(t.Property))
	}
	return out
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

func mergeAndUnmerge(t *testing.T, repo repository.Repository) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	surv := f.asset(&oamorg.Organization{ID: "globalsign:1", Name: "globalsign", Jurisdiction: "BE"})
	dup := f.asset(&oamorg.Organization{ID: "globalsign:2", Name: "globalsign", Jurisdiction: "NL",
		LegalName: "globalsign nv", RegistrationID: "0459134256", FoundingDate: "1996-01-01"})
	if _, err := repo.CreateEntityProperty(ctx, surv, &oamgen.SourceProperty{Source: "GLEIF", Confidence: 100}); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.CreateEntityProperty(ctx, dup, &oamgen.SourceProperty{Source: "DNS-SD", Confidence: 80}); err != nil {
		t.Fatal(err)
	}

	lei := f.asset(&oamgen.Identifier{UniqueID: "lei:875500H0WKURA9XATD59", ID: "875500H0WKURA9XATD59",
		Type: oamgen.LEICode})
	name := f.asset(&oamgen.Identifier{UniqueID: "org_name:GlobalSign, Inc.", ID: "GlobalSign, Inc.",
		Type: oamgen.OrganizationName})
	cr := f.asset(&contact.ContactRecord{DiscoveredAt: "https://globalsign.example"})
	loc := f.asset(&contact.Location{Address: "Diestsevest 14 3000 Leuven BE", City: "Leuven", Country: "BE"})

	f.edge(surv, lei, "id", "GLEIF")
	f.edge(dup, lei, "id", "GLEIF")
	f.edge(dup, name, "id", "DNS-SD")
	f.edge(cr, dup, "organization", "DNS-SD")
	f.edge(dup, loc, "legal_address", "GLEIF")
	f.edge(surv, dup, "subsidiary", "GLEIF")

	adapter := Adapter{Repo: repo}
	rec, err := adapter.MergeOrganizations(ctx, surv.ID, dup.ID, 90)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := repo.FindEntityById(ctx, dup.ID); err == nil {
		t.Fatal("the duplicate still exists after the merge")
	}

	links := f.links(surv.ID)
	for _, want := range []string{"out id " + lei.ID, "out id " + name.ID, "in organization " + cr.ID,
		"out legal_address " + loc.ID} {
		e, ok := links[want]
		if !ok {
			t.Fatalf("after the merge the survivor lacks %q: %v", want, links)
		}
		if !contains(f.edgeSources(e), ai.InferenceSource) {
			t.Errorf("moved edge %q lacks the %s source: %v", want, ai.InferenceSource, f.edgeSources(e))
		}
	}
	if !contains(f.edgeSources(links["out id "+name.ID]), "DNS-SD") {
		t.Error("a moved edge lost its original source")
	}
	if !contains(f.entitySources(surv.ID), "DNS-SD") || !contains(f.entitySources(surv.ID), "GLEIF") {
		t.Errorf("survivor sources after the merge: %v", f.entitySources(surv.ID))
	}

	// Empty fields are filled from the duplicate; a value is never replaced.
	ent, err := repo.FindEntityById(ctx, surv.ID)
	if err != nil {
		t.Fatal(err)
	}
	so := ent.Asset.(*oamorg.Organization)
	if so.LegalName != "globalsign nv" || so.RegistrationID != "0459134256" || so.Jurisdiction != "BE" {
		t.Errorf("survivor after the merge: %+v", so)
	}
	for _, field := range []string{"legal_name", "registration_id", "founding_date"} {
		if !contains(rec.FilledFields, field) {
			t.Errorf("filled fields %v lack %s", rec.FilledFields, field)
		}
	}
	if contains(rec.FilledFields, "jurisdiction") {
		t.Error("the survivor's jurisdiction was replaced")
	}

	var skipped int
	for _, m := range rec.Edges {
		if m.Skipped != "" {
			skipped++
		}
	}
	if skipped != 1 {
		t.Errorf("want the edge between the organizations skipped, got %d skipped", skipped)
	}

	// Another source records a moved relationship after the merge: undoing
	// the merge must keep it.
	if _, err := repo.CreateEdgeProperty(ctx, links["in organization "+cr.ID],
		&oamgen.SourceProperty{Source: "RDAP", Confidence: 100}); err != nil {
		t.Fatal(err)
	}

	restored, err := adapter.UnmergeOrganizations(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}

	links = f.links(surv.ID)
	if _, ok := links["out id "+name.ID]; ok {
		t.Error("undo left the moved name claim on the survivor")
	}
	if _, ok := links["out legal_address "+loc.ID]; ok {
		t.Error("undo left the moved address on the survivor")
	}
	if e, ok := links["out id "+lei.ID]; !ok {
		t.Error("undo removed the survivor's own LEI edge")
	} else if contains(f.edgeSources(e), ai.InferenceSource) {
		t.Error("undo left the amass-ai source on the survivor's own edge")
	}
	if e, ok := links["in organization "+cr.ID]; !ok {
		t.Error("undo deleted a relationship another source recorded after the merge")
	} else if contains(f.edgeSources(e), ai.InferenceSource) || !contains(f.edgeSources(e), "RDAP") {
		t.Errorf("relationship recorded since the merge has sources %v", f.edgeSources(e))
	}
	if contains(f.entitySources(surv.ID), "DNS-SD") || !contains(f.entitySources(surv.ID), "GLEIF") {
		t.Errorf("survivor sources after undo: %v", f.entitySources(surv.ID))
	}

	back := f.links(restored)
	for _, want := range []string{"out id " + lei.ID, "out id " + name.ID, "in organization " + cr.ID,
		"out legal_address " + loc.ID, "in subsidiary " + surv.ID} {
		e, ok := back[want]
		if !ok {
			t.Fatalf("the restored organization lacks %q: %v", want, back)
		}
		if contains(f.edgeSources(e), ai.InferenceSource) {
			t.Errorf("restored edge %q carries the %s source", want, ai.InferenceSource)
		}
	}
	if !contains(f.entitySources(restored), "DNS-SD") {
		t.Errorf("restored organization sources: %v", f.entitySources(restored))
	}

	ent, err = repo.FindEntityById(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	if o, ok := ent.Asset.(*oamorg.Organization); !ok || o.ID != "globalsign:2" || o.Jurisdiction != "NL" {
		t.Errorf("restored asset %+v", ent.Asset)
	}

	if _, err := adapter.MergeOrganizations(ctx, surv.ID, surv.ID, 90); err == nil {
		t.Error("an organization was merged into itself")
	}
	if _, err := adapter.MergeOrganizations(ctx, surv.ID, lei.ID, 90); err == nil {
		t.Error("an identifier was merged into an organization")
	}
}
