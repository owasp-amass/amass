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
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// The review flow for duplicates: the search records proposals, approve
// merges, retract restores, and a rejected proposal changes nothing.
func TestMergeReviewFlow(t *testing.T) {
	repo, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "merge-flow.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = repo.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	lei, err := repo.CreateAsset(ctx, &oamgen.Identifier{UniqueID: "lei:875500H0WKURA9XATD59",
		ID: "875500H0WKURA9XATD59", Type: oamgen.LEICode})
	if err != nil {
		t.Fatal(err)
	}
	for _, uid := range []string{"globalsign:1", "globalsign:2"} {
		o, err := repo.CreateAsset(ctx, &oamorg.Organization{ID: uid, Name: "globalsign", Jurisdiction: "BE",
			RegistrationID: "0459134256"})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := repo.CreateEdge(ctx, &dbt.Edge{FromEntity: o, ToEntity: lei,
			Relation: &oamgen.SimpleRelation{Name: "id"}}); err != nil {
			t.Fatal(err)
		}
	}
	for _, uid := range []string{"ithaka:1", "ithaka:2"} {
		if _, err := repo.CreateAsset(ctx, &oamorg.Organization{ID: uid, Name: "ithaka harbors"}); err != nil {
			t.Fatal(err)
		}
	}

	graph := oamrepo.Adapter{Repo: repo}
	journal := filepath.Join(t.TempDir(), "ai-review.jsonl")
	var out, errout bytes.Buffer
	if err := listDuplicates(ctx, graph, journal, "", false, &out, &errout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errout.String(), "2 new merge proposal(s)") {
		t.Fatalf("recording: %s", errout.String())
	}

	j := &ai.Journal{Path: journal}
	entries, err := j.DuplicateEntries()
	if err != nil || len(entries) != 2 {
		t.Fatalf("got %d entries, err %v", len(entries), err)
	}

	var merge, name ai.DuplicateProposal
	for _, e := range entries {
		if e.Proposal.Decision == ai.GapPropose {
			merge = e.Proposal
		} else {
			name = e.Proposal
		}
	}
	if merge.ID == "" || name.ID == "" {
		t.Fatalf("want one proposed and one review merge: %+v", entries)
	}

	// Recording again adds nothing.
	errout.Reset()
	if err := listDuplicates(ctx, graph, journal, "", false, &out, &errout); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(errout.String(), "0 new merge proposal(s)") {
		t.Fatalf("second recording: %s", errout.String())
	}

	out.Reset()
	if err := rejectProposal(journal, name.ID, "caffix", &out); err != nil {
		t.Fatal(err)
	}
	if err := approveMerge(ctx, graph, journal, name.ID, "caffix", &out); err == nil {
		t.Fatal("a rejected merge was applied")
	}

	out.Reset()
	if err := approveMerge(ctx, graph, journal, merge.ID, "caffix", &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Merged globalsign") {
		t.Fatalf("approve output: %s", out.String())
	}
	if _, err := repo.FindEntityById(ctx, merge.DuplicateID); err == nil {
		t.Fatal("the duplicate survived the approved merge")
	}

	out.Reset()
	if err := listProposals(journal, "", false, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Merge proposals:", merge.ID + "  APPLIED", name.ID + "  REJECTED"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("proposals listing lacks %q:\n%s", want, out.String())
		}
	}

	out.Reset()
	if err := retractMerge(ctx, graph, journal, merge.ID, "caffix", &out); err != nil {
		t.Fatal(err)
	}

	state, err := j.DuplicateState()
	if err != nil {
		t.Fatal(err)
	}
	restored := state[merge.ID].Outcome.RestoredID
	if state[merge.ID].Status != ai.ProposalRetracted || restored == "" {
		t.Fatalf("after retract: %+v", state[merge.ID])
	}
	ent, err := repo.FindEntityById(ctx, restored)
	if err != nil {
		t.Fatal(err)
	}
	if o := ent.Asset.(*oamorg.Organization); o.ID != "globalsign:2" && o.ID != "globalsign:1" {
		t.Fatalf("restored %+v", o)
	}
	if err := retractMerge(ctx, graph, journal, merge.ID, "caffix", &out); err == nil {
		t.Fatal("a merge was undone twice")
	}
}
