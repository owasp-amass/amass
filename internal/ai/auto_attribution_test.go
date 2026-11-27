// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

type recordingWriter struct {
	writes []lens.ProposedEdge
}

func (w *recordingWriter) ApplyOwnership(_ context.Context, e lens.ProposedEdge, _ int) (string, bool, error) {
	w.writes = append(w.writes, e)
	return "edge-1", false, nil
}

func attribute(t *testing.T, w review.OwnershipWriter, j *review.Journal, mode string) review.AttributionResult {
	t.Helper()

	return attributeWith(t, w, j, review.AttributionPolicy{Mode: mode})
}

func attributeWith(t *testing.T, w review.OwnershipWriter, j *review.Journal, policy review.AttributionPolicy) review.AttributionResult {
	t.Helper()

	g := graphtest.CampusGapsFixture()
	res, err := review.AttributeOwnership(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp"], w, j,
		policy)
	if err != nil {
		t.Fatal(err)
	}

	return res
}

func TestAttributeOwnershipWritesStrongProposalsOnce(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	w := &recordingWriter{}
	res := attribute(t, w, j, "auto")
	if len(res.Applied) != 1 || len(w.writes) != 1 {
		t.Fatalf("applied = %+v, writes = %+v", res.Applied, w.writes)
	}

	a := res.Applied[0]
	if a.Proposal.Asset != "https://rdap.example/alumni" || a.EdgeID != "edge-1" {
		t.Errorf("applied = %+v", a)
	}

	var gains []string
	for _, g := range a.Gains {
		gains = append(gains, g.Type+" "+graph.AssetLabel(g))
	}
	if strings.Join(gains, ",") != "DomainRecord owaspalumni.org,FQDN owaspalumni.org" {
		t.Errorf("gains = %v", gains)
	}

	entries, err := j.OwnershipEntries()
	if err != nil || len(entries) != 1 || entries[0].Status != review.ProposalApplied ||
		entries[0].Outcome.Reviewer != review.AutomaticReviewer {
		t.Fatalf("journal = %+v, %v", entries, err)
	}
	if again := attribute(t, w, j, "auto"); len(again.Applied) != 0 || len(w.writes) != 1 {
		t.Errorf("second pass wrote again: %+v", again.Applied)
	}
}

// A search cut short applies nothing: what it would have written waits for
// review, since the part not read may rule it out.
func TestAttributeOwnershipLeavesAPartialSearchForReview(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	// more subdomains than one read returns, on a reader that cannot page,
	// leave the search partial
	var nodes []graph.Relation
	for i := 0; i < graph.MaxEdgeRead+10; i++ {
		name := fmt.Sprintf("busy%d.owasp.org", i)
		g.Assets[name] = graph.Asset{ID: name, Type: "FQDN", Key: name, Content: map[string]any{"name": name}}
		nodes = append(nodes, graph.Relation{ID: "node-" + name, FromID: "owasp.org", ToID: name, Label: "node",
			Type: "SimpleRelation"})
	}
	g.Links = append(nodes, g.Links...)

	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	w := &recordingWriter{}
	res, err := review.AttributeOwnership(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog},
		g.Assets["owasp"], w, j, review.AttributionPolicy{Mode: "auto"})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial || !res.Report.Truncated {
		t.Fatalf("the search was not partial: %+v", res.Report)
	}
	if len(res.Applied) != 0 || len(w.writes) != 0 || len(res.Queued) == 0 {
		t.Errorf("applied %+v, writes %+v, queued %d; want nothing applied and the proposals queued",
			res.Applied, w.writes, len(res.Queued))
	}
}

func TestAttributeOwnershipHonorsReviewDecisions(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	ps := review.OwnershipProposals(gapReport(t))
	if _, err := j.SubmitOwnership(ps); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordOwnership(review.OwnershipOutcome{ProposalID: ps[0].ID, Status: review.ProposalRetracted, Reviewer: "jeff",
		EdgeID: "edge-0"}); err != nil {
		t.Fatal(err)
	}

	w := &recordingWriter{}
	if res := attribute(t, w, j, "auto"); len(res.Applied) != 0 || len(w.writes) != 0 {
		t.Errorf("a retracted proposal was written again: %+v", res.Applied)
	}
}

func TestAttributeOwnershipWritesPendingProposalsInAutoMode(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if res := attribute(t, nil, j, "journal"); len(res.Applied) != 0 || len(res.Queued) != 1 {
		t.Fatalf("journal mode = %+v", res)
	}

	w := &recordingWriter{}
	if res := attribute(t, w, j, "auto"); len(res.Applied) != 1 || len(res.Queued) != 0 {
		t.Errorf("auto mode after journal mode = applied %d, queued %d", len(res.Applied), len(res.Queued))
	}
}

func TestAttributeOwnershipNeedsAJournal(t *testing.T) {
	g := graphtest.CampusGapsFixture()
	if _, err := review.AttributeOwnership(context.Background(), g, graphtest.VendorCatalog{PlanCatalog: graphtest.TestOAMCatalog}, g.Assets["owasp"],
		&recordingWriter{}, nil, review.AttributionPolicy{Mode: "auto"}); err == nil {
		t.Error("attribution ran without a journal")
	}
}

func TestAttributionOnlyForAnchoredOrganizations(t *testing.T) {
	j := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	w := &recordingWriter{}

	// OWASP's footprint holds owasp.org: an enumeration of owasp.org
	// (or a name below it) attributes for OWASP.
	if res := attributeWith(t, w, j, review.AttributionPolicy{Mode: "auto", Anchors: []string{"www.owasp.org"}}); res.Unanchored ||
		len(res.Applied) != 1 {
		t.Fatalf("anchored run = %+v", res)
	}

	// An enumeration of another domain never attributes for OWASP, as for
	// a vendor pulled into its scope.
	j2 := &review.Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	res := attributeWith(t, &recordingWriter{}, j2, review.AttributionPolicy{Mode: "auto", Anchors: []string{"digicert.com"}})
	if !res.Unanchored || len(res.Applied) != 0 || len(res.Queued) != 0 {
		t.Errorf("unanchored run = %+v", res)
	}
	if entries, err := j2.OwnershipEntries(); err != nil || len(entries) != 0 {
		t.Errorf("an unanchored organization was journaled: %+v, %v", entries, err)
	}
}
