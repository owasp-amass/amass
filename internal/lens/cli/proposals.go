// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// listProposals prints every proposal in the journal, by kind.
func listProposals(j *review.Journal, format string, explicit bool, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	kinds, recs, err := listedKinds(j)
	if err != nil {
		return err
	}
	// Text unless JSON is asked for: -format defaults to json for search.
	if explicit && format == "json" {
		all := map[string]any{}
		for i, k := range kinds {
			all[k.key] = recs[i].entries(nil)
		}
		return writeJSON(out, all)
	}

	for i, k := range kinds {
		// the first kind is always shown, saying when it has none
		if i == 0 {
			_, err = fmt.Fprintln(out, recs[i].text(nil))
		} else if len(recs[i].records()) > 0 {
			_, err = fmt.Fprint(out, "\n"+k.heading+":\n\n"+recs[i].text(nil))
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// pendingProposals prints only the journal's proposals that are still awaiting
// a decision, so new ones can be surfaced for immediate review. The output has
// the same shape as listProposals, limited to Status == ProposalPending.
func pendingProposals(j *review.Journal, out io.Writer) error {
	return pendingProposalsLive(j, nil, out)
}

// EntityExists reports whether an entity is still in the Asset Database. The
// review listings use it to hide proposals left over from a database that was
// since wiped: their entities no longer exist, so they cannot be decided.
type EntityExists func(id string) bool

// live reports whether every entity is still stored, or true when there is no
// check.
func live(exists EntityExists, ids ...string) bool {
	if exists == nil {
		return true
	}
	for _, id := range ids {
		if id != "" && !exists(id) {
			return false
		}
	}
	return true
}

// pendingProposalsLive is pendingProposals, leaving out the proposals whose
// entities exists says are gone, and saying how many it left out.
func pendingProposalsLive(j *review.Journal, exists EntityExists, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	kinds, recs, err := listedKinds(j)
	if err != nil {
		return err
	}

	stale, total := 0, 0
	texts := make([]string, len(kinds))
	for i := range kinds {
		n := 0
		for _, r := range recs[i].records() {
			switch {
			case !r.isPending():
			case live(exists, r.entities...):
				n++
			default:
				stale++
			}
		}
		if n > 0 {
			texts[i] = recs[i].text(func(r record) bool { return r.isPending() && live(exists, r.entities...) })
		}
		total += n
	}
	staleNote := func() error {
		if stale == 0 {
			return nil
		}
		_, err := fmt.Fprintf(out, "\n%d older proposal(s) are hidden: their assets are no longer in the database "+
			"(it was reset since they were proposed), so they cannot be decided. Reset the review journal with "+
			"the database to clear them.\n", stale)
		return err
	}

	if total == 0 {
		if _, err := fmt.Fprintln(out, "No proposals are awaiting review."); err != nil {
			return err
		}
		return staleNote()
	}

	if _, err := fmt.Fprintf(out, "%d proposal(s) awaiting review:\n\n", total); err != nil {
		return err
	}
	for i, k := range kinds {
		if texts[i] == "" {
			continue
		}
		lead := "\n"
		if i == 0 {
			lead = ""
		}
		if _, err := fmt.Fprint(out, lead+k.heading+":\n\n"+texts[i]); err != nil {
			return err
		}
	}
	return staleNote()
}

// pendingProposal finds a proposal that has not been reviewed.
func pendingProposal(j *review.Journal, id, reviewer string) (review.OwnershipProposal, error) {
	if id == "" || reviewer == "" {
		return review.OwnershipProposal{}, errors.New("-proposal and -reviewer required")
	}

	state, err := j.OwnershipState()
	if err != nil {
		return review.OwnershipProposal{}, err
	}

	e, ok := state[id]
	if !ok {
		return review.OwnershipProposal{}, fmt.Errorf("no ownership proposal %s in the journal", id)
	}
	if e.Status != review.ProposalPending {
		return review.OwnershipProposal{}, fmt.Errorf("proposal %s is already %s", id, e.Status)
	}

	return e.Proposal, nil
}

// rejectProposal records a reviewer's rejection; nothing is written to the
// Asset Database.
func rejectProposal(j *review.Journal, id, reviewer string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	if isMergeProposal(id) {
		return rejectMerge(j, id, reviewer, out)
	}
	if isIdentityProposal(id) {
		return rejectIdentity(j, id, reviewer, out)
	}
	if isPersonNamedProposal(id) {
		return rejectPersonNamed(j, id, reviewer, out)
	}
	if review.IsOrgNamedProposal(id) {
		return rejectOrgNamed(j, id, reviewer, out)
	}
	if review.IsScopeExpansion(id) {
		return decideScopeExpansion(j, id, review.ProposalRejected, reviewer, out)
	}
	if review.IsNameKindProposal(id) {
		return rejectNameKind(j, id, reviewer, false, out)
	}

	if _, err := pendingProposal(j, id, reviewer); err != nil {
		return err
	}
	if err := j.RecordOwnership(review.OwnershipOutcome{ProposalID: id, Status: review.ProposalRejected,
		Reviewer: reviewer}); err != nil {
		return err
	}

	_, err := fmt.Fprintf(out, "Rejected %s; nothing was written.\n", id)
	return err
}

// approveProposal writes a pending proposal's relationship with the
// amass-ai source and the proposal's score as confidence, then records the
// edge in the journal.
func approveProposal(ctx context.Context, w review.OwnershipWriter, j *review.Journal, id, reviewer string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}

	p, err := pendingProposal(j, id, reviewer)
	if err != nil {
		return err
	}

	confidence := review.ProposalConfidence(p)
	edgeID, existed, err := w.ApplyOwnership(ctx, p.Edge, confidence)
	if err != nil {
		return fmt.Errorf("write %s: %w", p.Edge, err)
	}
	if err := j.RecordOwnership(review.OwnershipOutcome{ProposalID: id, Status: review.ProposalApplied,
		Reviewer: reviewer, EdgeID: edgeID}); err != nil {
		return fmt.Errorf("edge %s was written but the journal was not updated: %w", edgeID, err)
	}
	if existed {
		_, err = fmt.Fprintf(out, "Already recorded as edge %s: %s\n", edgeID, p.Edge)
		return err
	}

	_, err = fmt.Fprintf(out, "Wrote edge %s: %s (source %s, confidence %d)\n", edgeID, p.Edge,
		review.InferenceSource, confidence)
	return err
}

// ownershipRetractor removes a relationship written from a proposal.
type ownershipRetractor interface {
	RetractOwnership(ctx context.Context, edgeID string) (bool, error)
}

// retractProposal removes an applied proposal's amass-ai relationship and
// records the retraction, so automatic attribution never writes it again.
func retractProposal(ctx context.Context, r ownershipRetractor, j *review.Journal, id, reviewer string, out io.Writer) error {
	if j == nil {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	state, err := j.OwnershipState()
	if err != nil {
		return err
	}

	e, ok := state[id]
	if !ok {
		return fmt.Errorf("no ownership proposal %s in the journal", id)
	}
	if e.Status != review.ProposalApplied || e.Outcome == nil || e.Outcome.EdgeID == "" {
		return fmt.Errorf("proposal %s is %s, not applied", id, e.Status)
	}

	edgeID := e.Outcome.EdgeID
	removed, err := r.RetractOwnership(ctx, edgeID)
	if err != nil {
		return fmt.Errorf("retract edge %s: %w", edgeID, err)
	}
	if err := j.RecordOwnership(review.OwnershipOutcome{ProposalID: id, Status: review.ProposalRetracted,
		Reviewer: reviewer, EdgeID: edgeID}); err != nil {
		return err
	}
	if removed {
		_, err = fmt.Fprintf(out, "Removed edge %s: %s\n", edgeID, e.Proposal.Edge)
	} else {
		_, err = fmt.Fprintf(out, "Removed the %s source from edge %s; other sources also record it\n",
			review.InferenceSource, edgeID)
	}

	return err
}
