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

	"github.com/owasp-amass/amass/v5/internal/ai"
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

// tokenSeed stores Colgate's registration and a second domain that shares
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

	create("colgate", &org.Organization{ID: "colgate", Name: "Colgate University"})
	create("cr-colgate", &contact.ContactRecord{DiscoveredAt: "https://rdap.example/colgate"})
	create("dr", &registration.DomainRecord{Domain: "colgate.edu"})
	create("colgate.edu", &oamdns.FQDN{Name: "colgate.edu"})
	create("cr-arts", &contact.ContactRecord{DiscoveredAt: "https://rdap.example/arts"})
	create("dr-arts", &registration.DomainRecord{Domain: "colgate-arts.org"})
	create("colgate-arts.org", &oamdns.FQDN{Name: "colgate-arts.org"})
	create("unrelated.org", &oamdns.FQDN{Name: "unrelated.org"})

	link("cr-colgate", "organization", "colgate")
	link("dr", "registrant_contact", "cr-colgate")
	link("colgate.edu", "registration", "dr")
	link("dr-arts", "registrant_contact", "cr-arts")
	link("colgate-arts.org", "registration", "dr-arts")

	txt("colgate.edu", "google-site-verification=tok123")
	txt("colgate.edu", "v=spf1 include:_spf.colgate.edu -all")
	txt("colgate-arts.org", "google-site-verification=tok123")
	txt("colgate-arts.org", "v=spf1 include:_spf.colgate.edu ~all")
	txt("unrelated.org", "v=spf1 include:notcolgate.edu -all")
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

	found, _, err = adapter.FindByTagValue(ctx, "FQDN", "dns_record", "COLGATE.EDU", true, 10)
	var ids []string
	for _, f := range found {
		ids = append(ids, f.ID)
	}
	if err != nil || !slices.Contains(ids, ents["colgate-arts.org"].ID) || !slices.Contains(ids,
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

	owner, err := adapter.GetAsset(ctx, ents["colgate"].ID)
	if err != nil {
		t.Fatal(err)
	}

	j := &ai.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	res, err := ai.AttributeOwnership(ctx, adapter, Catalog{}, owner, adapter, j, ai.AttributionPolicy{Mode: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Applied) != 1 {
		t.Fatalf("applied = %+v; candidates = %+v", res.Applied, res.Report.Candidates)
	}

	p := res.Applied[0].Proposal
	if p.Asset != "colgate-arts.org" || p.Edge.From != "https://rdap.example/arts" ||
		!slices.Contains(p.SignalIDs, "txt_verification_token") ||
		!slices.Contains(p.SignalIDs, "email_auth_reference") {
		t.Errorf("proposal = %+v", p)
	}

	edges, err := db.OutgoingEdges(ctx, ents["cr-arts"], time.Time{}, "organization")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != ents["colgate"].ID {
		t.Errorf("organization edges = %v, %v", edges, err)
	}
	for _, c := range res.Report.Candidates {
		if c.AssetID == ents["unrelated.org"].ID {
			t.Errorf("a look-alike SPF include became a candidate: %+v", c)
		}
	}
}
