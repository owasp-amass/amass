// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/lens"
	"github.com/owasp-amass/amass/v5/internal/review"
)

// listProposals prints the journal's ownership proposals.
func listProposals(journalPath, format string, explicit bool, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &review.Journal{Path: journalPath}
	entries, err := j.OwnershipEntries()
	if err != nil {
		return err
	}

	merges, err := j.DuplicateEntries()
	if err != nil {
		return err
	}

	identities, err := j.IdentityEntries()
	if err != nil {
		return err
	}

	people, err := j.PersonNamedEntries()
	if err != nil {
		return err
	}

	relations, err := j.RelationEntries("")
	if err != nil {
		return err
	}
	// Text unless JSON is asked for: -format defaults to json for search.
	if explicit && format == "json" {
		return writeJSON(out, struct {
			Ownership   []review.OwnershipEntry   `json:"ownership"`
			Merges      []review.DuplicateEntry   `json:"merges"`
			Identities  []review.IdentityEntry    `json:"identities"`
			PersonNamed []review.PersonNamedEntry `json:"person_named"`
			Relations   []review.RelationEntry    `json:"relations"`
		}{entries, merges, identities, people, relations})
	}

	_, err = fmt.Fprintln(out, review.FormatOwnershipEntries(entries))
	if err == nil && len(merges) > 0 {
		_, err = fmt.Fprint(out, "\nMerge proposals:\n\n"+review.FormatDuplicateEntries(merges))
	}
	if err == nil && len(identities) > 0 {
		_, err = fmt.Fprint(out, "\nIdentity corrections:\n\n"+review.FormatIdentityEntries(identities))
	}
	if err == nil && len(people) > 0 {
		_, err = fmt.Fprint(out, "\nOrganizations recorded under a person's name:\n\n"+
			review.FormatPersonNamedEntries(people))
	}
	if err == nil && len(relations) > 0 {
		_, err = fmt.Fprint(out, "\nRelationship proposals:\n\n"+review.FormatRelationEntries(relations))
	}
	return err
}

// pendingProposals prints only the journal's proposals that are still awaiting
// a decision, so new ones can be surfaced for immediate review. The output has
// the same shape as listProposals, limited to Status == ProposalPending.
func pendingProposals(journalPath string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &review.Journal{Path: journalPath}

	entries, err := j.OwnershipEntries()
	if err != nil {
		return err
	}
	merges, err := j.DuplicateEntries()
	if err != nil {
		return err
	}
	identities, err := j.IdentityEntries()
	if err != nil {
		return err
	}
	people, err := j.PersonNamedEntries()
	if err != nil {
		return err
	}
	relations, err := j.RelationEntries("")
	if err != nil {
		return err
	}

	entries = filterPendingOwnership(entries)
	merges = filterPendingDuplicate(merges)
	identities = filterPendingIdentity(identities)
	people = filterPendingPersonNamed(people)
	relations = filterPendingRelation(relations)

	total := len(entries) + len(merges) + len(identities) + len(people) + len(relations)
	if total == 0 {
		_, err = fmt.Fprintln(out, "No proposals are awaiting review.")
		return err
	}

	_, err = fmt.Fprintf(out, "%d proposal(s) awaiting review:\n\n", total)
	if err == nil && len(entries) > 0 {
		_, err = fmt.Fprint(out, "Ownership relationships:\n\n"+review.FormatOwnershipEntries(entries))
	}
	if err == nil && len(merges) > 0 {
		_, err = fmt.Fprint(out, "\nMerge proposals:\n\n"+review.FormatDuplicateEntries(merges))
	}
	if err == nil && len(identities) > 0 {
		_, err = fmt.Fprint(out, "\nIdentity corrections:\n\n"+review.FormatIdentityEntries(identities))
	}
	if err == nil && len(people) > 0 {
		_, err = fmt.Fprint(out, "\nOrganizations recorded under a person's name:\n\n"+
			review.FormatPersonNamedEntries(people))
	}
	if err == nil && len(relations) > 0 {
		_, err = fmt.Fprint(out, "\nRelationship proposals:\n\n"+review.FormatRelationEntries(relations))
	}
	return err
}

// PendingSummary counts the proposals in a journal that are still awaiting a
// decision, grouped by kind. It lets a finished enumeration, or any client
// polling a run, tell the user how many proposals are waiting and of what kind
// without their having to run `amass review proposals` — closing the gap where
// proposals surfaced only to someone who knew to look.
type PendingSummary struct {
	Ownership   int `json:"ownership"`
	Merges      int `json:"merges"`
	Identities  int `json:"identities"`
	PersonNamed int `json:"person_named"`
	Relations   int `json:"relations"`
	Total       int `json:"total"`
}

// PendingProposalsSummary counts, by kind, the journal's proposals that are
// still awaiting a decision. It reads the same journal `amass review` reads, so
// its counts match what a review session would show.
func PendingProposalsSummary(journalPath string) (PendingSummary, error) {
	var s PendingSummary
	if journalPath == "" {
		return s, errors.New("-journal required")
	}

	j := &review.Journal{Path: journalPath}
	entries, err := j.OwnershipEntries()
	if err != nil {
		return s, err
	}
	merges, err := j.DuplicateEntries()
	if err != nil {
		return s, err
	}
	identities, err := j.IdentityEntries()
	if err != nil {
		return s, err
	}
	people, err := j.PersonNamedEntries()
	if err != nil {
		return s, err
	}
	relations, err := j.RelationEntries("")
	if err != nil {
		return s, err
	}

	s.Ownership = len(filterPendingOwnership(entries))
	s.Merges = len(filterPendingDuplicate(merges))
	s.Identities = len(filterPendingIdentity(identities))
	s.PersonNamed = len(filterPendingPersonNamed(people))
	s.Relations = len(filterPendingRelation(relations))
	s.Total = s.Ownership + s.Merges + s.Identities + s.PersonNamed + s.Relations
	return s, nil
}

// Line renders the summary as a single sentence that names the counts by kind
// and points at the review command, or "" when nothing is pending (so a caller
// can print it only when there is something to say).
func (s PendingSummary) Line() string {
	if s.Total == 0 {
		return ""
	}

	var parts []string
	if s.Merges > 0 {
		parts = append(parts, fmt.Sprintf("%d possible duplicate %s", s.Merges,
			plural(s.Merges, "organization", "organizations")))
	}
	if s.Identities > 0 {
		parts = append(parts, fmt.Sprintf("%d identity %s", s.Identities,
			plural(s.Identities, "correction", "corrections")))
	}
	if s.PersonNamed > 0 {
		parts = append(parts, fmt.Sprintf("%d %s recorded under a person's name", s.PersonNamed,
			plural(s.PersonNamed, "organization", "organizations")))
	}
	if s.Ownership > 0 {
		parts = append(parts, fmt.Sprintf("%d ownership %s", s.Ownership,
			plural(s.Ownership, "relationship", "relationships")))
	}
	if s.Relations > 0 {
		parts = append(parts, fmt.Sprintf("%d inferred %s", s.Relations,
			plural(s.Relations, "relationship", "relationships")))
	}

	return fmt.Sprintf("%d proposal(s) awaiting review: %s — review with 'amass review proposals'",
		s.Total, strings.Join(parts, ", "))
}

// plural picks the singular or plural noun for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func filterPendingOwnership(in []review.OwnershipEntry) []review.OwnershipEntry {
	out := in[:0:0]
	for _, e := range in {
		if e.Status == review.ProposalPending {
			out = append(out, e)
		}
	}
	return out
}

func filterPendingDuplicate(in []review.DuplicateEntry) []review.DuplicateEntry {
	out := in[:0:0]
	for _, e := range in {
		if e.Status == review.ProposalPending {
			out = append(out, e)
		}
	}
	return out
}

func filterPendingIdentity(in []review.IdentityEntry) []review.IdentityEntry {
	out := in[:0:0]
	for _, e := range in {
		if e.Status == review.ProposalPending {
			out = append(out, e)
		}
	}
	return out
}

func filterPendingPersonNamed(in []review.PersonNamedEntry) []review.PersonNamedEntry {
	out := in[:0:0]
	for _, e := range in {
		if e.Status == review.ProposalPending {
			out = append(out, e)
		}
	}
	return out
}

func filterPendingRelation(in []review.RelationEntry) []review.RelationEntry {
	out := in[:0:0]
	for _, e := range in {
		if e.Status == review.ProposalPending {
			out = append(out, e)
		}
	}
	return out
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
func rejectProposal(journalPath, id, reviewer string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	if isMergeProposal(id) {
		return rejectMerge(journalPath, id, reviewer, out)
	}
	if isIdentityProposal(id) {
		return rejectIdentity(journalPath, id, reviewer, out)
	}
	if isPersonNamedProposal(id) {
		return rejectPersonNamed(journalPath, id, reviewer, out)
	}

	j := &review.Journal{Path: journalPath}
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
func approveProposal(ctx context.Context, w review.OwnershipWriter, journalPath, id, reviewer string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}

	j := &review.Journal{Path: journalPath}
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
func retractProposal(ctx context.Context, r ownershipRetractor, journalPath, id, reviewer string, out io.Writer) error {
	if journalPath == "" {
		return errors.New("-journal required")
	}
	if id == "" || reviewer == "" {
		return errors.New("-proposal and -reviewer required")
	}

	j := &review.Journal{Path: journalPath}
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

// listSignals prints the ownership signal catalog: each signal with what it
// finds, why it counts, its guards and when it can mislead. Text is the
// default; markdown is docs/ai/SIGNALS.md.
func listSignals(format string, explicit bool, out io.Writer) error {
	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.SignalsText())
		return err
	case format == "markdown":
		_, err := fmt.Fprint(out, lens.SignalsMarkdown())
		return err
	case format == "json":
		return writeJSON(out, lens.OwnershipSignals())
	}

	return fmt.Errorf("signals format %q: use text, json or markdown", format)
}

// listDuplicateSignals prints the duplicate-organization signal catalog.
// Text is the default; markdown is docs/ai/DUPLICATES.md.
func listDuplicateSignals(format string, explicit bool, out io.Writer) error {
	switch {
	case !explicit || format == "text":
		_, err := fmt.Fprint(out, lens.DuplicateSignalsText())
		return err
	case format == "markdown":
		_, err := fmt.Fprint(out, lens.DuplicateSignalsMarkdown())
		return err
	case format == "json":
		return writeJSON(out, lens.DuplicateSignals())
	}

	return fmt.Errorf("duplicate-signals format %q: use text, json or markdown", format)
}
