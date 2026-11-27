// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oampeople "github.com/owasp-amass/open-asset-model/people"
)

// Converting a person stored under an organization's name moves its
// relationships to the Organization the contact record already names (a
// contact's person becomes its organization), keeps what an Organization
// cannot have for undo, and undoing restores the person exactly.
func TestConvertPersonToOrganization(t *testing.T) {
	for _, reuse := range []bool{true, false} {
		repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "convert.db"))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		a := Adapter{Repo: repo}

		name := "Acme Widgets LLC"
		cr := mustAsset(t, repo, &contact.ContactRecord{DiscoveredAt: "https://rdap.example/entity/acme"})
		person := mustAsset(t, repo, &oampeople.Person{ID: name, FullName: name, FirstName: "Acme",
			MiddleName: "Widgets", FamilyName: "LLC"})
		phone := mustAsset(t, repo, &contact.Phone{Raw: "+13155550100", E164: "+13155550100"})
		addr := mustAsset(t, repo, &contact.StreetAddress{Address: "1 Main St Utica NY US", City: "Utica",
			Country: "US"})
		mustLink(t, repo, cr, "person", person)
		mustLink(t, repo, person, "phone", phone)
		mustLink(t, repo, person, "street_address", addr)

		var org *dbt.Entity
		if reuse {
			org = mustAsset(t, repo, &oamorg.Organization{ID: "acme:1", Name: semantics.OrgNameKey(name)})
			mustLink(t, repo, cr, "organization", org)
		}

		// the check finds the person, with the organization to reuse
		report, err := lens.FindOrgNamedPersons(ctx, a)
		if err != nil || len(report.Candidates) != 1 {
			t.Fatalf("reuse %v: report %+v, %v", reuse, report, err)
		}
		p := report.Candidates[0]
		if p.PersonID != person.ID || len(p.Reasons) == 0 || (reuse && p.OrgID != org.ID) || (!reuse && p.OrgID != "") {
			t.Fatalf("reuse %v: candidate %+v", reuse, p)
		}

		rec, err := a.ConvertPersonToOrganization(ctx, p)
		if err != nil {
			t.Fatalf("reuse %v: %v", reuse, err)
		}
		if rec.OrgCreated == reuse || (reuse && rec.OrgID != org.ID) {
			t.Fatalf("reuse %v: record %+v", reuse, rec)
		}
		if ent, err := repo.FindEntityById(ctx, person.ID); err == nil && ent != nil {
			t.Fatalf("reuse %v: the person is still stored", reuse)
		}
		// the phone cannot belong to an Organization; the contact's
		// organization edge already existed when reused
		wantAdded := 1
		if !reuse {
			wantAdded = 2
		}
		if len(rec.Dropped) != 1 || rec.Dropped[0].Label != "phone" || len(rec.AddedEdges) != wantAdded {
			t.Fatalf("reuse %v: dropped %+v, added %v", reuse, rec.Dropped, rec.AddedEdges)
		}
		orgEnt, _ := repo.FindEntityById(ctx, rec.OrgID)
		if n := countEdges(t, repo, cr, "organization"); n != 1 {
			t.Fatalf("reuse %v: %d organization edges from the contact record", reuse, n)
		}
		if n := countEdges(t, repo, orgEnt, "street_address"); n != 1 {
			t.Fatalf("reuse %v: %d street_address edges on the organization", reuse, n)
		}

		restored, err := a.RevertPersonConversion(ctx, rec)
		if err != nil {
			t.Fatalf("reuse %v: revert: %v", reuse, err)
		}
		back, err := repo.FindEntityById(ctx, restored)
		if err != nil || back == nil {
			t.Fatalf("reuse %v: the person was not restored: %v", reuse, err)
		}
		if countEdges(t, repo, back, "phone") != 1 || countEdges(t, repo, back, "street_address") != 1 ||
			countEdges(t, repo, cr, "person") != 1 {
			t.Errorf("reuse %v: the person's relationships were not restored", reuse)
		}
		if ent, err := repo.FindEntityById(ctx, rec.OrgID); reuse != (err == nil && ent != nil) {
			t.Errorf("reuse %v: the organization's presence after undo is wrong", reuse)
		} else if reuse && countEdges(t, repo, ent, "street_address") != 0 {
			t.Errorf("reuse %v: the moved relationship stayed on the organization", reuse)
		}
		_ = repo.Close()
	}
}

func mustAsset(t *testing.T, repo repository.Repository, a oam.Asset) *dbt.Entity {
	t.Helper()
	ent, err := repo.CreateAsset(context.Background(), a)
	if err != nil {
		t.Fatal(err)
	}
	return ent
}

func mustLink(t *testing.T, repo repository.Repository, from *dbt.Entity, label string, to *dbt.Entity) {
	t.Helper()
	if _, err := repo.CreateEdge(context.Background(), &dbt.Edge{Relation: &general.SimpleRelation{Name: label},
		FromEntity: from, ToEntity: to}); err != nil {
		t.Fatal(err)
	}
}

func countEdges(t *testing.T, repo repository.Repository, from *dbt.Entity, label string) int {
	t.Helper()
	edges, _ := repo.OutgoingEdges(context.Background(), from, time.Time{}, label)
	return len(edges)
}
