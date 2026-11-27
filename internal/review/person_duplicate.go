// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/lens"
)

// Person merges reuse the DuplicateProposal journal machinery — the proposal,
// outcome, state and entry types, and SubmitDuplicates/RecordDuplicate — and
// differ only in the proposal ID prefix and in which merge is applied. A person
// merge is always review-gated: it is proposed, never applied automatically.

// PersonDuplicatePrefix starts every person-merge proposal ID, so an apply can
// tell a person merge from an organization merge by the proposal alone.
const PersonDuplicatePrefix = "pdup-"

// personMergeScore is the confidence written on relationships a person merge
// moves. A name-variant-plus-shared-link match is probable, not certain, and a
// human has approved it, so the confidence is moderate.
const personMergeScore = 0.75

// PersonMerger merges two person records in the Asset Database and undoes a
// merge from its record. Undo is the same operation as for organizations.
type PersonMerger interface {
	MergePersons(ctx context.Context, survivorID, duplicateID string, confidence int) (MergeRecord, error)
	UnmergeOrganizations(ctx context.Context, rec MergeRecord) (UnmergeResult, error)
}

// Merger can apply both organization and person merges, so one reviewer can
// decide a merge proposal of either kind — the proposal ID says which.
type Merger interface {
	OrganizationMerger
	MergePersons(ctx context.Context, survivorID, duplicateID string, confidence int) (MergeRecord, error)
}

// IsPersonMerge reports whether a merge proposal ID is a person merge.
func IsPersonMerge(id string) bool {
	return len(id) >= len(PersonDuplicatePrefix) && id[:len(PersonDuplicatePrefix)] == PersonDuplicatePrefix
}

// PersonDuplicateProposalID is a stable identifier for merging two persons,
// built from their keys (their full names, which survive an undone merge) so a
// rejected or undone merge is recognized and never applied again. It does not
// depend on which one survives.
func PersonDuplicateProposalID(a, b graph.Asset) string {
	ids := []string{proposalKey(a), proposalKey(b)}
	sort.Strings(ids)
	sum := sha256.Sum256([]byte(ids[0] + "\x00" + ids[1]))
	return PersonDuplicatePrefix + hex.EncodeToString(sum[:8])
}

// PersonDuplicateProposals turns a person-duplicate report's candidates into
// review-gated merge proposals.
func PersonDuplicateProposals(r lens.PersonDuplicateReport) []DuplicateProposal {
	var out []DuplicateProposal
	now := time.Now().UTC()
	for _, c := range r.Candidates {
		out = append(out, DuplicateProposal{
			ID:          PersonDuplicateProposalID(c.Survivor, c.Duplicate),
			Survivor:    graph.AssetLabel(c.Survivor),
			SurvivorID:  c.SurvivorID,
			Duplicate:   graph.AssetLabel(c.Duplicate),
			DuplicateID: c.DuplicateID,
			Score:       personMergeScore,
			Decision:    lens.GapReview,
			Signals:     c.Signals,
			CreatedAt:   now,
		})
	}

	return out
}

// ApplyPersonMerge merges a pending person proposal's duplicate into its
// survivor and records the merge, so it can be undone. It is only ever called
// for a proposal a human has approved.
func ApplyPersonMerge(ctx context.Context, m PersonMerger, j *Journal, p DuplicateProposal,
	reviewer string) (MergeRecord, error) {
	rec, err := m.MergePersons(ctx, p.SurvivorID, p.DuplicateID, MergeConfidence(p))
	if err != nil {
		return rec, fmt.Errorf("merge %s [%s] into %s [%s]: %w", p.Duplicate, p.DuplicateID, p.Survivor,
			p.SurvivorID, err)
	}
	if err := j.RecordDuplicate(DuplicateOutcome{ProposalID: p.ID, Status: ProposalApplied, Reviewer: reviewer,
		Merge: &rec}); err != nil {
		return rec, fmt.Errorf("%s was merged but the journal was not updated: %w", p.Duplicate, err)
	}

	return rec, nil
}
