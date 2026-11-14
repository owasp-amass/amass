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
	oam "github.com/owasp-amass/open-asset-model"
	oamcert "github.com/owasp-amass/open-asset-model/certificate"
	"github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// A department the family lens finds is proposed as an org_unit
// relationship; approving writes it with the amass-ai source, retracting
// removes it, and it never trains the ownership model.
func TestFamilyDepartmentProposal(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "family-flow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	create := func(a oam.Asset) *dbt.Entity {
		e, err := repo.CreateAsset(ctx, a)
		if err != nil {
			t.Fatal(err)
		}
		return e
	}
	link := func(from, to *dbt.Entity, label string) {
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: from, ToEntity: to,
			Relation: &oamgen.SimpleRelation{Name: label}}); err != nil {
			t.Fatal(err)
		}
	}

	ua := create(&oamorg.Organization{ID: "ua:1", Name: "university at albany"})
	its := create(&oamorg.Organization{ID: "ua:2", Name: "ualbany its enterprise infrastructure"})
	apex := create(&oamdns.FQDN{Name: "albany.edu"})
	www := create(&oamdns.FQDN{Name: "www.albany.edu"})
	link(apex, www, "node")

	cert := create(&oamcert.TLSCertificate{Version: "3", SerialNumber: "1", SubjectCommonName: "www.albany.edu",
		IssuerCommonName: "R11", NotBefore: "2026-01-01T00:00:00Z", NotAfter: "2027-01-01T00:00:00Z"})
	link(cert, www, "common_name")
	crCert := create(&contact.ContactRecord{DiscoveredAt: "cert"})
	link(cert, crCert, "subject_contact")
	link(crCert, ua, "organization")

	dr := create(&oamreg.DomainRecord{Domain: "albany.edu", Name: "albany.edu", ID: "albany.edu"})
	link(apex, dr, "registration")
	crITS := create(&contact.ContactRecord{DiscoveredAt: "whois"})
	link(dr, crITS, "technical_contact")
	link(crITS, its, "organization")
	email := create(&oamgen.Identifier{UniqueID: "email:dnsadmin@albany.edu", ID: "dnsadmin@albany.edu",
		Type: oamgen.EmailAddress})
	link(crITS, email, "id")

	graph := oamrepo.Adapter{Repo: repo}
	journal := filepath.Join(t.TempDir(), "ai-review.jsonl")
	var out, errout bytes.Buffer
	if err := listFamily(ctx, graph, "albany.edu", journal, "", false, &out, &errout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Departments:") || !strings.Contains(errout.String(), "1 department") {
		t.Fatalf("family:\n%s\n%s", out.String(), errout.String())
	}

	j := &ai.Journal{Path: journal}
	entries, err := j.OwnershipEntries()
	if err != nil || len(entries) != 1 || entries[0].Proposal.Kind != ai.ProposalKindOrgUnit {
		t.Fatalf("entries = %+v, %v", entries, err)
	}
	id := entries[0].Proposal.ID

	if err := approveProposal(ctx, graph, journal, id, "caffix", &out); err != nil {
		t.Fatal(err)
	}
	edges, err := repo.OutgoingEdges(ctx, ua, time.Time{}, "org_unit")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != its.ID {
		t.Fatalf("org_unit edges = %v, %v", edges, err)
	}

	entries, _ = j.OwnershipEntries()
	if rows, _ := ai.OwnershipTrainingSet(entries); len(rows) != 0 {
		t.Errorf("a department decision became %d training row(s)", len(rows))
	}
	out.Reset()
	if err := listProposals(journal, "", false, &out); err != nil || !strings.Contains(out.String(), "is a unit of") {
		t.Errorf("listing:\n%s", out.String())
	}

	if err := retractProposal(ctx, graph, journal, id, "caffix", &out); err != nil {
		t.Fatal(err)
	}
	if edges, err := repo.OutgoingEdges(ctx, ua, time.Time{}, "org_unit"); err == nil && len(edges) != 0 {
		t.Errorf("retract left %d org_unit edge(s)", len(edges))
	}
}
