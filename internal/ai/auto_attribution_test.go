// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

type recordingWriter struct {
	writes []ProposedEdge
}

func (w *recordingWriter) ApplyOwnership(_ context.Context, e ProposedEdge, _ int) (string, bool, error) {
	w.writes = append(w.writes, e)
	return "edge-1", false, nil
}

func attribute(t *testing.T, w OwnershipWriter, j *Journal, mode string) AttributionResult {
	t.Helper()

	return attributeWith(t, w, j, AttributionPolicy{Mode: mode})
}

func attributeWith(t *testing.T, w OwnershipWriter, j *Journal, policy AttributionPolicy) AttributionResult {
	t.Helper()

	g := campusGapsFixture()
	res, err := AttributeOwnership(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate"], w, j,
		policy)
	if err != nil {
		t.Fatal(err)
	}

	return res
}

func TestAttributeOwnershipWritesStrongProposalsOnce(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
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
		gains = append(gains, g.Type+" "+AssetLabel(g))
	}
	if strings.Join(gains, ",") != "DomainRecord colgatealumni.org,FQDN colgatealumni.org" {
		t.Errorf("gains = %v", gains)
	}

	entries, err := j.OwnershipEntries()
	if err != nil || len(entries) != 1 || entries[0].Status != ProposalApplied ||
		entries[0].Outcome.Reviewer != AutomaticReviewer {
		t.Fatalf("journal = %+v, %v", entries, err)
	}
	if again := attribute(t, w, j, "auto"); len(again.Applied) != 0 || len(w.writes) != 1 {
		t.Errorf("second pass wrote again: %+v", again.Applied)
	}
}

func TestAttributeOwnershipHonorsReviewDecisions(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	ps := OwnershipProposals(gapReport(t))
	if _, err := j.SubmitOwnership(ps); err != nil {
		t.Fatal(err)
	}
	if err := j.RecordOwnership(OwnershipOutcome{ProposalID: ps[0].ID, Status: ProposalRetracted, Reviewer: "jeff",
		EdgeID: "edge-0"}); err != nil {
		t.Fatal(err)
	}

	w := &recordingWriter{}
	if res := attribute(t, w, j, "auto"); len(res.Applied) != 0 || len(w.writes) != 0 {
		t.Errorf("a retracted proposal was written again: %+v", res.Applied)
	}
}

func TestAttributeOwnershipWritesPendingProposalsInAutoMode(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	if res := attribute(t, nil, j, "journal"); len(res.Applied) != 0 || len(res.Queued) != 1 {
		t.Fatalf("journal mode = %+v", res)
	}

	w := &recordingWriter{}
	if res := attribute(t, w, j, "auto"); len(res.Applied) != 1 || len(res.Queued) != 0 {
		t.Errorf("auto mode after journal mode = applied %d, queued %d", len(res.Applied), len(res.Queued))
	}
}

func TestAttributeOwnershipNeedsAJournal(t *testing.T) {
	g := campusGapsFixture()
	if _, err := AttributeOwnership(context.Background(), g, vendorCatalog{testOAMCatalog}, g.assets["colgate"],
		&recordingWriter{}, nil, AttributionPolicy{Mode: "auto"}); err == nil {
		t.Error("attribution ran without a journal")
	}
}

func TestAttributionOnlyForAnchoredOrganizations(t *testing.T) {
	j := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	w := &recordingWriter{}

	// Colgate's footprint holds colgate.edu: an enumeration of colgate.edu
	// (or a name below it) attributes for Colgate.
	if res := attributeWith(t, w, j, AttributionPolicy{Mode: "auto", Anchors: []string{"www.colgate.edu"}}); res.Unanchored ||
		len(res.Applied) != 1 {
		t.Fatalf("anchored run = %+v", res)
	}

	// An enumeration of another domain never attributes for Colgate, as for
	// a vendor pulled into its scope.
	j2 := &Journal{Path: filepath.Join(t.TempDir(), "review.jsonl")}
	res := attributeWith(t, &recordingWriter{}, j2, AttributionPolicy{Mode: "auto", Anchors: []string{"digicert.com"}})
	if !res.Unanchored || len(res.Applied) != 0 || len(res.Queued) != 0 {
		t.Errorf("unanchored run = %+v", res)
	}
	if entries, err := j2.OwnershipEntries(); err != nil || len(entries) != 0 {
		t.Errorf("an unanchored organization was journaled: %+v, %v", entries, err)
	}
}
