// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"os"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

func TestDecisionsSinceReportsNewItemsOnly(t *testing.T) {
	path, first := journalWithProposal(t)

	// An empty cursor starts from now: nothing already in the journal is
	// reported.
	base, err := DecisionsSince(path, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(base.Items) != 0 || base.Cursor == "" {
		t.Fatalf("baseline = %+v, want no items and a cursor", base)
	}

	// Nothing appended: same cursor, no items.
	same, err := DecisionsSince(path, base.Cursor)
	if err != nil || len(same.Items) != 0 || same.Cursor != base.Cursor {
		t.Fatalf("unchanged journal = %+v, %v", same, err)
	}

	// A new proposal is reported as pending.
	edge := lens.ProposedEdge{FromID: "3", FromType: "ContactRecord", From: "https://rdap.example/press",
		Label: "organization", RelationType: "SimpleRelation", ToID: "2", ToType: "Organization",
		To: "Synthetic University"}
	second := review.OwnershipProposal{ID: review.ProposalID(edge), Owner: "Synthetic University", OwnerID: "2",
		Asset: edge.From, AssetID: "3", AssetType: "ContactRecord", Edge: edge, Score: 0.8,
		Decision: lens.GapPropose, Signals: []string{"identity via address"}}
	if _, err := path.SubmitOwnership([]review.OwnershipProposal{second}); err != nil {
		t.Fatal(err)
	}

	got, err := DecisionsSince(path, base.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Items) != 1 || got.Items[0].ID != second.ID || got.Items[0].Kind != "ownership" ||
		got.Items[0].Status != DecisionPending || got.Items[0].Summary == "" {
		t.Fatalf("after a new proposal = %+v", got.Items)
	}

	// A human rejection is not something to announce.
	if err := rejectProposal(path, first.ID, "jeff", &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	rejected, err := DecisionsSince(path, got.Cursor)
	if err != nil || len(rejected.Items) != 0 {
		t.Fatalf("after a human rejection = %+v, %v", rejected.Items, err)
	}

	// A change the AI classifier applied on its own is announced as applied.
	if err := approveProposal(context.Background(), &fakeOwnershipWriter{}, path, second.ID,
		review.AutomaticReviewer, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	applied, err := DecisionsSince(path, rejected.Cursor)
	if err != nil {
		t.Fatal(err)
	}
	if len(applied.Items) != 1 || applied.Items[0].ID != second.ID || applied.Items[0].Status != DecisionApplied ||
		applied.Items[0].Reviewer != review.AutomaticReviewer {
		t.Fatalf("after an AI-applied decision = %+v", applied.Items)
	}

	// list_proposals applied lists the item itself, not only a count.
	text, err := AppliedProposalsText(path)
	if err != nil || !strings.Contains(text, second.ID) || !strings.Contains(text, review.AutomaticReviewer) {
		t.Errorf("applied listing = %q, %v", text, err)
	}

	// A line still being written is left for the next call.
	f, err := os.OpenFile(path.Path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(`{"kind":"ownership_proposal","data":`); err != nil {
		t.Fatal(err)
	}
	f.Close()
	partial, err := DecisionsSince(path, applied.Cursor)
	if err != nil || len(partial.Items) != 0 || partial.Cursor != applied.Cursor {
		t.Fatalf("a partial line moved the cursor: %+v, %v", partial, err)
	}

	// A journal reset alongside a database wipe is reported, not an error.
	if err := os.WriteFile(path.Path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	reset, err := DecisionsSince(path, applied.Cursor)
	if err != nil || !reset.Reset || reset.Cursor != "0" {
		t.Fatalf("after a reset = %+v, %v", reset, err)
	}

	if _, err := DecisionsSince(path, "not-a-number"); err == nil {
		t.Error("an invalid cursor was accepted")
	}
}
