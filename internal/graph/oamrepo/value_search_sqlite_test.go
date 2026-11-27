// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package oamrepo

import (
	"context"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/review"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
	"github.com/owasp-amass/open-asset-model/registration"
)

// tokenSeed stores OWASP's registration and a second domain that shares
// its site verification token and includes its SPF record.
func tokenSeed(t *testing.T, db repository.Repository) map[string]*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	ents := map[string]*dbt.Entity{}
	create := func(name string, a oam.Asset) {
		e, err := db.CreateAsset(ctx, a)
		if err != nil {
			t.Fatal(err)
		}

		ents[name] = e
	}
	link := func(from, label, to string) {
		if _, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &general.SimpleRelation{Name: label},
			FromEntity: ents[from], ToEntity: ents[to]}); err != nil {
			t.Fatal(err)
		}
	}
	txt := func(name, data string) {
		if _, err := db.CreateEntityProperty(ctx, ents[name], &oamdns.DNSRecordProperty{PropertyName: "dns_record",
			Header: oamdns.RRHeader{RRType: 16, Class: 1}, Data: data}); err != nil {
			t.Fatal(err)
		}
	}

	create("owasp", &org.Organization{ID: "owasp", Name: "OWASP Foundation"})
	create("cr-owasp", &contact.ContactRecord{DiscoveredAt: "https://rdap.example/owasp"})
	create("dr", &registration.DomainRecord{Domain: "owasp.org"})
	create("owasp.org", &oamdns.FQDN{Name: "owasp.org"})
	create("cr-arts", &contact.ContactRecord{DiscoveredAt: "https://rdap.example/arts"})
	create("dr-arts", &registration.DomainRecord{Domain: "owasp-arts.org"})
	create("owasp-arts.org", &oamdns.FQDN{Name: "owasp-arts.org"})
	create("unrelated.org", &oamdns.FQDN{Name: "unrelated.org"})

	link("cr-owasp", "organization", "owasp")
	link("dr", "registrant_contact", "cr-owasp")
	link("owasp.org", "registration", "dr")
	link("dr-arts", "registrant_contact", "cr-arts")
	link("owasp-arts.org", "registration", "dr-arts")

	txt("owasp.org", "google-site-verification=tok123")
	txt("owasp.org", "v=spf1 include:_spf.owasp.org -all")
	txt("owasp-arts.org", "google-site-verification=tok123")
	txt("owasp-arts.org", "v=spf1 include:_spf.owasp.org ~all")
	txt("unrelated.org", "v=spf1 include:notowasp.org -all")
	return ents
}

func TestValueSearchOnSQLite(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "values.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	ents := tokenSeed(t, db)
	adapter := Adapter{Repo: db}
	ctx := context.Background()

	found, more, err := adapter.FindByTagValue(ctx, "FQDN", "dns_record", "google-site-verification=tok123", false, 10)
	if err != nil || more || len(found) != 2 {
		t.Fatalf("exact = %v, %v, %v", found, more, err)
	}

	found, _, err = adapter.FindByTagValue(ctx, "FQDN", "dns_record", "OWASP.ORG", true, 10)
	var ids []string
	for _, f := range found {
		ids = append(ids, f.ID)
	}
	if err != nil || !slices.Contains(ids, ents["owasp-arts.org"].ID) || !slices.Contains(ids,
		ents["unrelated.org"].ID) {
		t.Errorf("contains = %v, %v (the matcher, not the search, rules out look-alikes)", ids, err)
	}
}

func TestTokenAndSPFAttributeOwnershipOnSQLite(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "attribution.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	ents := tokenSeed(t, db)
	adapter := Adapter{Repo: db}
	ctx := context.Background()

	owner, err := adapter.GetAsset(ctx, ents["owasp"].ID)
	if err != nil {
		t.Fatal(err)
	}

	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	res, err := review.AttributeOwnership(ctx, adapter, Catalog{}, owner, adapter, j, review.AttributionPolicy{Mode: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 1 {
		t.Fatalf("applied = %+v; candidates = %+v", res.Applied, res.Report.Candidates)
	}

	p := res.Applied[0].Proposal
	if p.Asset != "owasp-arts.org" || p.Edge.From != "https://rdap.example/arts" ||
		!slices.Contains(p.SignalIDs, "txt-verification-token") ||
		!slices.Contains(p.SignalIDs, "spf-authorizes") {
		t.Errorf("proposal = %+v", p)
	}

	edges, err := db.OutgoingEdges(ctx, ents["cr-arts"], time.Time{}, "organization")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != ents["owasp"].ID {
		t.Errorf("organization edges = %v, %v", edges, err)
	}
	for _, c := range res.Report.Candidates {
		if c.AssetID == ents["unrelated.org"].ID {
			t.Errorf("a look-alike SPF include became a candidate: %+v", c)
		}
	}
}
