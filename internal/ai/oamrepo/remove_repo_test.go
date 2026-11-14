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
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/people"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// A person-named organization is found, removed with its relationship and
// source, and restored with them by the retraction.
func TestRemoveAndRestorePersonNamedOrganization(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "person.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	f := mergeFixture{t: t, ctx: ctx, repo: repo}

	org := f.asset(&oamorg.Organization{ID: "eric:1", Name: "Eric Torgersen"})
	person := f.asset(&people.Person{ID: "eric", FullName: "Eric Torgersen", FirstName: "Eric",
		FamilyName: "Torgersen"})
	cr := f.asset(&contact.ContactRecord{DiscoveredAt: "whois"})
	dr := f.asset(&oamreg.DomainRecord{Domain: "torgersen.example", Name: "torgersen.example",
		ID: "torgersen.example"})
	f.edge(dr, cr, "registrant_contact", "WHOIS")
	f.edge(cr, org, "organization", "WHOIS")
	f.edge(cr, person, "person", "WHOIS")

	adapter := Adapter{Repo: repo}
	r, err := ai.FindPersonNamedOrganizations(ctx, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Candidates) != 1 || r.Candidates[0].OrgID != org.ID {
		t.Fatalf("candidates = %+v", r.Candidates)
	}

	rec, err := adapter.RemoveOrganization(ctx, org.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Edges) != 1 || rec.Edges[0].Outgoing || rec.Edges[0].OtherID != cr.ID {
		t.Fatalf("removal record edges = %+v", rec.Edges)
	}
	if got, err := repo.FindEntityById(ctx, org.ID); err == nil && got != nil {
		t.Fatal("the organization is still stored")
	}
	if left, _ := ai.FindPersonNamedOrganizations(ctx, adapter); len(left.Candidates) != 0 {
		t.Errorf("still found after removal: %+v", left.Candidates)
	}

	restored, err := adapter.RestoreOrganization(ctx, rec)
	if err != nil {
		t.Fatal(err)
	}
	back, err := adapter.GetAsset(ctx, restored)
	if err != nil || back.Type != "Organization" {
		t.Fatalf("restored %s: %+v, %v", restored, back, err)
	}
	in, err := adapter.Edges(ctx, restored, "in", "organization", time.Time{})
	if err != nil || len(in) != 1 || in[0].FromID != cr.ID {
		t.Fatalf("restored relationships = %+v, %v", in, err)
	}
	e, err := repo.FindEdgeById(ctx, in[0].ID)
	if err != nil {
		t.Fatal(err)
	}
	if srcs := f.edgeSources(e); len(srcs) != 1 || srcs[0] != "WHOIS" {
		t.Errorf("restored relationship sources = %v", srcs)
	}
}
