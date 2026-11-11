// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// The review flow for identity corrections: the check records proposals,
// approve corrects, retract restores, and nothing is corrected unreviewed.
func TestIdentityReviewFlow(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "identity-flow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	edge := func(from, to *dbt.Entity, label, src string) {
		e, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: from, ToEntity: to,
			Relation: &oamgen.SimpleRelation{Name: label}})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdgeProperty(ctx, e, &oamgen.SourceProperty{Source: src, Confidence: 100}); err != nil {
			t.Fatal(err)
		}
	}
	stripe, err := repo.CreateAsset(ctx, &oamorg.Organization{ID: "stripe:1", Name: "stripe", LegalName: "stripe",
		Jurisdiction: "BE", RegistrationID: "0888373015"})
	if err != nil {
		t.Fatal(err)
	}
	name, _ := repo.CreateAsset(ctx, &oamgen.Identifier{UniqueID: "org_name:Stripe, LLC.", ID: "Stripe, LLC.",
		Type: oamgen.OrganizationName})
	lei, _ := repo.CreateAsset(ctx, &oamgen.Identifier{UniqueID: "lei:894500EDC64T52PGFL08",
		ID: "894500EDC64T52PGFL08", Type: oamgen.LEICode})
	cr, _ := repo.CreateAsset(ctx, &contact.ContactRecord{DiscoveredAt: "https://stripe.example"})
	loc, _ := repo.CreateAsset(ctx, &contact.Location{Address: "354 Oyster Point Blvd South San Francisco CA US",
		City: "South San Francisco", Country: "US"})
	edge(stripe, name, "id", "TLSCert-Expansion")
	edge(stripe, lei, "id", "GLEIF")
	edge(cr, stripe, "organization", "TLSCert-Expansion")
	edge(cr, loc, "location", "TLSCert-Expansion")

	graph := oamrepo.Adapter{Repo: repo}
	journal := filepath.Join(t.TempDir(), "ai-review.jsonl")
	var out, errout bytes.Buffer
	if err := listIdentityConflicts(ctx, graph, journal, "", false, &out, &errout); err != nil {
		t.Fatal(err)
	}
	// Same name, different country: the Belgian record is not Stripe, LLC's.
	if !strings.Contains(out.String(), "jurisdiction BE, but its contact records are in US") {
		t.Fatalf("report:\n%s", out.String())
	}
	if !strings.Contains(errout.String(), "1 new identity correction(s)") {
		t.Fatalf("recording: %s", errout.String())
	}

	entries, err := (&ai.Journal{Path: journal}).IdentityEntries()
	if err != nil || len(entries) != 1 {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	id := entries[0].Proposal.ID

	out.Reset()
	if err := approveProposal(ctx, graph, journal, id, "caffix", &out); err == nil {
		t.Fatal("an identity correction was approved as an ownership proposal")
	}
	if err := approveIdentity(ctx, graph, journal, id, "caffix", &out); err != nil {
		t.Fatal(err)
	}
	ent, _ := repo.FindEntityById(ctx, stripe.ID)
	if o := ent.Asset.(*oamorg.Organization); o.Jurisdiction != "" || o.LegalName != "" {
		t.Fatalf("after approve: %+v", o)
	}

	out.Reset()
	if err := listProposals(journal, "", false, &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Identity corrections:") || !strings.Contains(out.String(), id+"  APPLIED") {
		t.Errorf("proposals listing:\n%s", out.String())
	}

	if err := retractIdentity(ctx, graph, journal, id, "caffix", &out); err != nil {
		t.Fatal(err)
	}
	ent, _ = repo.FindEntityById(ctx, stripe.ID)
	if o := ent.Asset.(*oamorg.Organization); o.Jurisdiction != "BE" || o.LegalName != "stripe" {
		t.Fatalf("after retract: %+v", o)
	}
	if err := retractIdentity(ctx, graph, journal, id, "caffix", &out); err == nil {
		t.Fatal("a correction was undone twice")
	}
}
