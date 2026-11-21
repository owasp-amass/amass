// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/owasp-amass/amass/v5/internal/review"
)

// Decision item statuses: a proposal awaiting the user's decision, or a change
// the AI classifier already applied on its own.
const (
	DecisionPending = "pending"
	DecisionApplied = "applied"
)

// DecisionItem is one thing a watcher should tell the user about: a proposal
// that now awaits a decision, or a change the AI classifier applied to the
// graph without a human (an "amass-ai" reviewer). Summary is the same text
// "amass review" shows for it.
type DecisionItem struct {
	Kind     string `json:"kind"`
	ID       string `json:"id"`
	Status   string `json:"status"`
	Reviewer string `json:"reviewer,omitempty"`
	Summary  string `json:"summary"`
	// EntityIDs are the stored assets the item is about, so a listing can
	// leave out items left over from a database that was since wiped.
	EntityIDs []string `json:"entity_ids,omitempty"`
}

// Live reports whether every entity the item is about is still stored.
func (d DecisionItem) Live(exists EntityExists) bool { return live(exists, d.EntityIDs...) }

func (d DecisionItem) key() string { return d.Kind + "\x00" + d.ID + "\x00" + d.Status }

// DecisionChanges are the decision items that appeared in the journal after a
// cursor, and the cursor to pass next time.
type DecisionChanges struct {
	Items []DecisionItem `json:"items"`
	// Cursor marks how far the journal has been read (a byte offset at a line
	// boundary). An empty cursor in a request means "from now on".
	Cursor string `json:"cursor"`
	// Reset is true when the journal shrank below the cursor (it was reset
	// alongside a database wipe), so every current item is reported again.
	Reset bool `json:"reset,omitempty"`
}

// DecisionsSince reports the pending proposals and AI-applied changes that
// appeared in the journal after cursor. It rebuilds the decision state as of
// the cursor and as of the journal's last complete line, with the same readers
// "amass review" uses, and returns the items present now that were not then —
// so it needs no timestamps and keeps no state between calls. An empty cursor
// returns no items and the cursor for the journal's current end.
func DecisionsSince(journalPath, cursor string) (DecisionChanges, error) {
	var out DecisionChanges
	if journalPath == "" {
		return out, errors.New("no review journal is configured")
	}

	var start int64
	if cursor != "" {
		n, err := strconv.ParseInt(cursor, 10, 64)
		if err != nil || n < 0 {
			return out, fmt.Errorf("invalid cursor %q", cursor)
		}
		start = n
	}

	// Nothing was appended: answer from a stat, so a watcher can poll cheaply.
	info, err := os.Stat(journalPath)
	switch {
	case errors.Is(err, os.ErrNotExist):
		info = nil
	case err != nil:
		return out, err
	}
	var size int64
	if info != nil {
		size = info.Size()
	}
	if cursor != "" && size == start {
		out.Cursor = cursor
		return out, nil
	}

	data, err := readJournal(journalPath)
	if err != nil {
		return out, err
	}
	// Read only complete lines: a line still being written is left for the
	// next call.
	end := int64(bytes.LastIndexByte(data, '\n') + 1)
	data = data[:end]
	out.Cursor = strconv.FormatInt(end, 10)
	if cursor == "" {
		return out, nil
	}
	if start > end {
		out.Reset, start = true, 0
	}
	if start == end {
		return out, nil
	}

	before, err := decisionItemsOf(data[:start])
	if err != nil {
		return out, err
	}
	now, err := decisionItemsOf(data)
	if err != nil {
		return out, err
	}

	seen := make(map[string]bool, len(before))
	for _, d := range before {
		seen[d.key()] = true
	}
	for _, d := range now {
		if !seen[d.key()] {
			out.Items = append(out.Items, d)
		}
	}

	return out, nil
}

func readJournal(path string) ([]byte, error) {
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return io.ReadAll(f)
}

// decisionItemsOf reads the decision items of a journal's contents through a
// temporary copy, so the review package's readers see exactly these lines.
func decisionItemsOf(data []byte) ([]DecisionItem, error) {
	f, err := os.CreateTemp("", "amass-review-*.jsonl")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())

	if _, err := f.Write(data); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	return DecisionItems(f.Name())
}

// DecisionItems lists the journal's proposals awaiting a decision and the
// changes the AI classifier applied automatically, by kind: the same
// proposals PendingProposalsSummary counts and the same changes
// AppliedByAISummary counts.
func DecisionItems(journalPath string) ([]DecisionItem, error) {
	j := &review.Journal{Path: journalPath}
	var out []DecisionItem
	add := func(kind, id, status, reviewer, summary string, entities ...string) {
		out = append(out, DecisionItem{Kind: kind, ID: id, Status: status, Reviewer: reviewer,
			Summary: strings.TrimSpace(summary), EntityIDs: entities})
	}

	owned, err := j.OwnershipEntries()
	if err != nil {
		return nil, err
	}
	for _, e := range owned {
		text := review.FormatOwnershipEntries([]review.OwnershipEntry{e})
		switch {
		case e.Status == review.ProposalPending:
			add("ownership", e.Proposal.ID, DecisionPending, "", text, e.Proposal.Edge.FromID, e.Proposal.Edge.ToID)
		case e.Status == review.ProposalApplied && e.Outcome != nil && isAIReviewer(e.Outcome.Reviewer):
			add("ownership", e.Proposal.ID, DecisionApplied, e.Outcome.Reviewer, text, e.Proposal.Edge.FromID,
				e.Proposal.Edge.ToID)
		}
	}

	merges, err := j.DuplicateEntries()
	if err != nil {
		return nil, err
	}
	for _, e := range merges {
		text := review.FormatDuplicateEntries([]review.DuplicateEntry{e})
		switch {
		case e.Status == review.ProposalPending:
			add("merge", e.Proposal.ID, DecisionPending, "", text, e.Proposal.SurvivorID, e.Proposal.DuplicateID)
		case e.Status == review.ProposalApplied && e.Outcome != nil && isAIReviewer(e.Outcome.Reviewer):
			add("merge", e.Proposal.ID, DecisionApplied, e.Outcome.Reviewer, text, e.Proposal.SurvivorID)
		}
	}

	identities, err := j.IdentityEntries()
	if err != nil {
		return nil, err
	}
	for _, e := range identities {
		text := review.FormatIdentityEntries([]review.IdentityEntry{e})
		switch {
		case e.Status == review.ProposalPending:
			add("identity", e.Proposal.ID, DecisionPending, "", text, e.Proposal.OrgID)
		case e.Status == review.ProposalApplied && e.Outcome != nil && isAIReviewer(e.Outcome.Reviewer):
			add("identity", e.Proposal.ID, DecisionApplied, e.Outcome.Reviewer, text, e.Proposal.OrgID)
		}
	}

	people, err := j.PersonNamedEntries()
	if err != nil {
		return nil, err
	}
	for _, e := range filterPendingPersonNamed(people) {
		add("person_named", e.Proposal.ID, DecisionPending, "",
			review.FormatPersonNamedEntries([]review.PersonNamedEntry{e}), e.Proposal.OrgID, e.Proposal.PersonID)
	}

	relations, err := j.RelationEntries("")
	if err != nil {
		return nil, err
	}
	for _, e := range filterPendingRelation(relations) {
		add("relation", e.Proposal.ID, DecisionPending, "",
			review.FormatRelationEntries([]review.RelationEntry{e}), e.Proposal.FromID, e.Proposal.ToID)
	}

	expansions, err := j.AppliedScopeExpansions()
	if err != nil {
		return nil, err
	}
	for _, e := range expansions {
		if e.Status != review.ProposalApplied || !isAIReviewer(e.Reviewer) {
			continue
		}

		text := fmt.Sprintf("Scope expanded to %s %s for %s (confidence %d)", e.Kind(), e.Asset, e.Org,
			e.Confidence)
		if len(e.Signals) > 0 {
			text += ": " + strings.Join(e.Signals, ", ")
		}
		add("scope_expansion", e.ID, DecisionApplied, e.Reviewer, text, e.OrgID)
	}

	return out, nil
}
