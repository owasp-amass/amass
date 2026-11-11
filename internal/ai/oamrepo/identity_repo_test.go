// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/postgres"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

func TestIdentityConflictsOnSQLite(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "identity.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	identityConflicts(t, repo)
}

// TestIdentityConflictsOnPostgres runs the same check against the empty
// PostgreSQL database named by AMASS_AI_POSTGRES_IDENTITY_DSN.
func TestIdentityConflictsOnPostgres(t *testing.T) {
	dsn := os.Getenv("AMASS_AI_POSTGRES_IDENTITY_DSN")
	if dsn == "" {
		t.Skip("AMASS_AI_POSTGRES_IDENTITY_DSN is not set")
	}

	repo, err := assetdb.New(postgres.Postgres, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	identityConflicts(t, repo)
}

func identityConflicts(t *testing.T, repo repository.Repository) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	ident := func(idtype, value string) *dbt.Entity {
		return f.asset(&oamgen.Identifier{UniqueID: idtype + ":" + value, ID: value, Type: idtype})
	}

	// Apple Inc., from a certificate, with GLEIF's record for a French
	// company named APPLE 12.
	apple := f.asset(&oamorg.Organization{ID: "apple:1", Name: "apple", LegalName: "apple 12", Jurisdiction: "FR",
		RegistrationID: "532672227", FoundingDate: "2011-06-01"})
	f.edge(apple, ident(oamgen.OrganizationName, "Apple Inc."), "id", "TLSCert-Expansion")
	f.edge(apple, ident(oamgen.LegalName, "APPLE 12"), "id", "GLEIF")
	f.edge(apple, ident("ocid", "fr/532672227"), "id", "GLEIF")
	lei := f.edge(apple, ident(oamgen.LEICode, "969500RDBEVTUKOLE690"), "id", "GLEIF")
	if _, err := repo.CreateEdgeProperty(ctx, lei, &oamgen.SourceProperty{Source: "RDAP", Confidence: 100}); err != nil {
		t.Fatal(err)
	}
	cr := f.asset(&contact.ContactRecord{DiscoveredAt: "https://apple.example"})
	f.edge(cr, apple, "organization", "TLSCert-Expansion")
	f.edge(cr, f.asset(&contact.Location{Address: "One Apple Park Way Cupertino CA US", City: "Cupertino",
		Country: "US"}), "location", "TLSCert-Expansion")
	paris := f.asset(&contact.Location{Address: "12 rue de Paris 75008 Paris FR", City: "Paris", Country: "FR"})
	f.edge(apple, paris, "legal_address", "GLEIF")

	// Colgate University: its legal identity agrees with its evidence.
	colgate := f.asset(&oamorg.Organization{ID: "colgate:1", Name: "colgate university",
		LegalName: "colgate university", Jurisdiction: "US-NY"})
	f.edge(colgate, ident(oamgen.OrganizationName, "Colgate University"), "id", "RDAP")
	f.edge(colgate, ident(oamgen.LegalName, "Colgate University"), "id", "GLEIF")
	cr2 := f.asset(&contact.ContactRecord{DiscoveredAt: "https://rdap.example/colgate"})
	f.edge(cr2, colgate, "organization", "RDAP")
	f.edge(cr2, f.asset(&contact.Location{Address: "13 Oak Drive Hamilton NY US", City: "Hamilton", Country: "US"}),
		"location", "RDAP")

	adapter := Adapter{Repo: repo}
	r, err := ai.FindIdentityConflicts(ctx, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Conflicts) != 1 || r.Conflicts[0].OrgID != apple.ID {
		t.Fatalf("conflicts = %+v", r.Conflicts)
	}

	c := r.Conflicts[0]
	reasons := strings.Join(c.Reasons, "\n")
	if !strings.Contains(reasons, "jurisdiction FR") || !strings.Contains(reasons, "matches none") {
		t.Errorf("reasons = %s", reasons)
	}
	if len(c.EdgeIDs) != 4 {
		t.Errorf("want the 4 GLEIF relationships, got %d", len(c.EdgeIDs))
	}

	rec, err := adapter.CorrectIdentity(ctx, c)
	if err != nil {
		t.Fatal(err)
	}

	ent, err := repo.FindEntityById(ctx, apple.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o := ent.Asset.(*oamorg.Organization); o.LegalName != "" || o.Jurisdiction != "" || o.RegistrationID != "" ||
		o.FoundingDate != "" || o.Name != "apple" {
		t.Errorf("after the correction: %+v", o)
	}

	links := f.links(apple.ID)
	for key := range links {
		if strings.Contains(key, "legal_address") {
			t.Errorf("a GLEIF-only address survived: %s", key)
		}
	}
	if e, ok := links["out id "+ident(oamgen.LEICode, "969500RDBEVTUKOLE690").ID]; !ok {
		t.Error("the LEI another source also recorded was deleted")
	} else if srcs := f.edgeSources(e); contains(srcs, "GLEIF") || !contains(srcs, "RDAP") {
		t.Errorf("LEI sources after the correction: %v", srcs)
	}
	if _, ok := links["out id "+ident(oamgen.OrganizationName, "Apple Inc.").ID]; !ok {
		t.Error("an independent name claim was removed")
	}
	if _, ok := links["out id "+ident(oamgen.LegalName, "APPLE 12").ID]; ok {
		t.Error("the GLEIF legal name claim survived")
	}

	if err := adapter.UndoIdentityCorrection(ctx, rec); err != nil {
		t.Fatal(err)
	}

	ent, err = repo.FindEntityById(ctx, apple.ID)
	if err != nil {
		t.Fatal(err)
	}
	if o := ent.Asset.(*oamorg.Organization); o.LegalName != "apple 12" || o.Jurisdiction != "FR" ||
		o.RegistrationID != "532672227" {
		t.Errorf("after undo: %+v", o)
	}

	links = f.links(apple.ID)
	if _, ok := links["out legal_address "+paris.ID]; !ok {
		t.Error("undo did not restore the address")
	}
	if e, ok := links["out id "+ident(oamgen.LegalName, "APPLE 12").ID]; !ok {
		t.Error("undo did not restore the legal name claim")
	} else if !contains(f.edgeSources(e), "GLEIF") {
		t.Errorf("restored claim sources: %v", f.edgeSources(e))
	}
	if e := links["out id "+ident(oamgen.LEICode, "969500RDBEVTUKOLE690").ID]; !contains(f.edgeSources(e), "GLEIF") {
		t.Errorf("undo did not restore the GLEIF source on the LEI: %v", f.edgeSources(e))
	}

	// A proposal reviewed against another identity is refused.
	stale := c
	stale.LegalName = "something else"
	if _, err := adapter.CorrectIdentity(ctx, stale); err == nil {
		t.Error("corrected an identity that changed since the proposal")
	}
}
